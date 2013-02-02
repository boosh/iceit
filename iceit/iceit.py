#!/bin/env python

# Put your files on ice. Compress, encrypt, obfuscate and archive them on Amazon Glacier.
#
# Inspired by duply/duplicity and bakthat.

import aaargh
import boto.glacier
import boto.s3
from boto.s3.key import Key
from boto.s3.connection import Location
from boto.exception import S3ResponseError
from bz2 import BZ2File
import ConfigParser
from copy import copy
from datetime import datetime
import getpass
import gnupg
import hashlib
import logging
import os
import random
import re
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, DateTime, select
import string
import sys
from tempfile import mkstemp, mkdtemp, TemporaryFile

log = logging.getLogger(__name__)

if not log.handlers:
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

class Catalogue(object):
    """
    Encapsulates the catalogue - the database of files stored, their modification times and hashes.
    """
    def __init__(self, dbpath):
        self.tables = {}
        self.engine = create_engine('sqlite:///%s' % dbpath)
        self.__create_tables()

        self.conn = self.engine.connect()

    def __create_tables(self):
        "Create necessary tables"
        log.info("Creating DB tables...")
        metadata = MetaData()
        self.tables['files'] = Table('files', metadata,
            Column('id', Integer, primary_key=True),
            Column('source_path', String),
            Column('aws_archive_id', String),
            Column('file_mtime', DateTime),
            Column('source_hash', String),
            Column('processed_hash', String),
            Column('last_backed_up', DateTime)
        )

        metadata.create_all(self.engine)
        log.info("DB tables created...")

    def get(self, file_path):
        "Get a file entry or return an empty list if not found"
        file_table = self.tables['files']

        log.debug("Searching for file %s in catalogue..." % file_path)
        query = select([file_table], file_table.c.source_path==file_path)
        result = self.conn.execute(query)

        rows = result.fetchall()

        log.debug("%d record(s) found." % len(rows))

        return rows

    def add_item(self, item, id=None):
        """
        Add an item to the catalogue, or update the one with the given ID

        @param dict item - A dictionary where keys correspond to column names in the 'files' table.
        """
        log.debug("Adding item to catalogue with data: %s" % item)
        file_table = self.tables['files']
        if id:
            # update
            query = file_table.update().where(file_table.c.id==id).values(item)
        else:
            # insert
            query = file_table.insert().values(item)

        return self.conn.execute(query)


class Config(object):
    """
    Manages the application configuration. Different config profiles correspond to subdirectories of the
    main config directory and allow different sets of configs to be used.
    """
    def __init__(self, config_profile, config_dir=os.path.expanduser("~/.iceit")):
        self.config_profile = config_profile
        self.config_dir = os.path.join(config_dir, self.config_profile)
        self.config = ConfigParser.SafeConfigParser()
        self.config.read(self.get_config_file_path())

    def is_valid(self):
        "Return a boolean indicating whether the current config profile exists and is valid"
        return os.path.exists(self.get_config_file_path())

    def get_config_file_path(self):
        "Return the path to the config file"
        return os.path.join(self.config_dir, 'iceit.conf')

    def get_public_key_path(self):
        "Return the path to the public key file"
        return os.path.join(self.config_dir, 'public.key')

    def get_private_key_path(self):
        "Return the path to the private key file"
        return os.path.join(self.config_dir, 'private.key')

    def get_catalogue_path(self):
        "Return the full path to the catalogue file"
        return os.path.join(self.config_dir, self.config.get('catalogue', 'name'))

    def get(self, *args, **kwargs):
        "Get a config value from the underlying config system"
        return self.config.get(*args, **kwargs)

    def getboolean(self, *args, **kwargs):
        "Get a config value from the underlying config system"
        return self.config.getboolean(*args, **kwargs)

    def write_config_file(self, settings):
        """
        Create default config.

        @param settings - dict containing AWS credentials
        """
        if not os.path.isdir(self.config_dir):
            os.makedirs(self.config_dir)

        if not self.config.has_section('aws'):
            self.config.add_section("aws")

        self.config.set("aws", "access_key", settings['aws']['access_key'])
        self.config.set("aws", "secret_key", settings['aws']['secret_key'])
        self.config.set("aws", "s3_location", settings['aws']['s3_location'])
        self.config.set("aws", "s3_bucket", settings['aws']['s3_bucket'])
        self.config.set("aws", "glacier_region", settings['aws']['glacier_region'])
        self.config.set("aws", "glacier_vault", settings['aws']['glacier_vault'])

        # default config values
        if not self.config.has_section('catalogue'):
            self.config.add_section('catalogue')
            # name of the sqlite3 database file (under the config directory) to use as the catalogue
            self.config.set('catalogue', 'name', 'catalogue.db')
            # whether to store hashes of the source files in the catalogue
            self.config.set('catalogue', 'store_source_file_hashes', 'true')

        if not self.config.has_section('encryption'):
            self.config.add_section('encryption')

        # ID of the key to use to encrypt files. Encryption will be disabled if blank
        self.config.set('encryption', 'key_id', settings['encryption']['key_id'])

        if not self.config.has_section('processing'):
            self.config.add_section('processing')
            # absolute files names matching the following regexes will not be compressed
            self.config.set('processing', 'disable_compression_patterns',
                '^.*\.avi$,^.*\.mp(3|4)$,^.*\.mpe?g$,^.*\.jpe?g$,^.*\.bz2$,^.*\.gz(ip)?$')
            # Whether to create a single archive per directory (True), or to process files individually
#            self.config.set('processing', 'create_one_archive_per_directory', 'true')
            # The minimum number of files to add to an archive when creating one per directory automatically
#            self.config.set('processing', 'min_files_per_directory_archive', '2')
            # Whether to obfuscate file names before uploading them
            self.config.set('processing', 'obfuscate_file_names', 'true')
            # File patterns (as reg exes) to exclude from backing up. Separate multiple with commas.
            self.config.set('processing', 'exclude_patterns', '^.*/desktop\.ini$')

        self.config.write(open(self.get_config_file_path(), "w"))

        log.info("Config written to %s" % self.get_config_file_path())


class Encryptor(object):
    """
    All crypto-related methods.
    """
    def __init__(self, key_id):
        """
        @param string key_id - The ID of the key to use for encryption
        """
        self.gpg = gnupg.GPG()
        self.set_key_id(key_id)

    def set_key_id(self, key_id):
        "Set the key ID"
        self.key_id = key_id

    def get_key_id(self):
        "Return the encryption key ID"
        return self.key_id

    def list_secret_keys(self):
        "Return a list of secret keys"
        return self.gpg.list_keys(True)

    def generate_key_pair(self, key_type="RSA", length=4096, options={}):
        """
        Generates a GPG key pair.

        @param dict options - Must contain the following keys:
            - name_real - Real name of the user identity represented by the key
            - name_comment - A comment to attach to the user ID
            - name_email - An email address for the user
        """
        log.info("Generating GPG key pair")
        input_data = self.gpg.gen_key_input(key_type=key_type, key_length=length, name_real=options['name_real'],
            name_comment=options['name_comment'], name_email=options['name_email'])
        key = self.gpg.gen_key(input_data)
        log.info("Key generated")
        self.key_id = key.fingerprint.strip()
        return self.key_id

    def export_keys(self, public_key_dest, private_key_dest):
        """
        Export the current key to files called public_key_dest and private_key_dest

        @param string public_key_dest - Path to write the public key to
        @param string private_key_dest - Path to write the private key to
        """
        log.info("Writing public key with ID %s to %s" % (self.key_id, public_key_dest))
        with open(public_key_dest, 'w') as pub_key_file:
            public_key = self.gpg.export_keys(self.key_id)
            pub_key_file.write(public_key)

        public_key_length = os.path.getsize(public_key_dest)
        if public_key_length == 0:
            raise IceItException("Error - failed to export public key")

        log.info("Public key written.")

        log.info("Writing private key to %s" % private_key_dest)
        with open(private_key_dest, 'w') as private_key_file:
            private_key_file.write(self.gpg.export_keys(self.key_id, True))

        private_key_length = os.path.getsize(private_key_dest)
        if private_key_length == 0:
            raise IceItException("Error - failed to export private key")

        log.info("Private key written.")

    def encrypt(self, input_file, output_dir, output_extension=".gpg"):
        """
        Encrypt the given file using the public key.

        @param string input_file - The file to encrypt.
        @param string output_dir - The file to write the encrypted file to.
        @param string output_extension - An extension to append to the file
        """
        encrypted_file_name = os.path.join(output_dir, os.path.basename(input_file) + output_extension)
        log.info("Encrypting %s to %s" % (input_file, encrypted_file_name))

        if not self.key_id:
            raise IceItException("Can't encrypt files. Set the key ID first.")

        if not os.path.exists(input_file):
            raise IceItException("Can't encrypt non-existent file '%s'" % input_file)

        with open(input_file, 'r') as file:
            self.gpg.encrypt_file(file, self.key_id, sign=self.key_id, armor=False, output=encrypted_file_name)

        if not os.path.exists(encrypted_file_name) or os.path.getsize(encrypted_file_name) == 0:
            raise IceItException("Failed to encrypt file. Perhaps you specified a key that needs a passphrase?")

        log.info("Encryption complete.")
        return encrypted_file_name


class FileFinder(object):
    "Finds files using different methods"

    def __init__(self, path, recursive=False):
        """
        @param string start - Path to scan
        @param bool recursive - Whether to scan recursively or just return
            files in the input directory.
        """
        self.path = path
        self.recursive = recursive
        self.files = None

    def get_files(self):
        "Return a set of files for the given operating mode."
        if self.recursive:
            self.files = self.__get_files_recursive()
        else:
            self.files = self.__get_files_non_recursive()

        return self.files

    def __get_files_non_recursive(self):
        "Only return files from the input directory."
        for (path, dirs, files) in os.walk(self.path):
            return set([os.path.join(path, f) for f in files])

    def __get_files_recursive(self):
        "Return all matching files"
        output = set()

        for (path, dirs, files) in os.walk(self.path):
            full_files = [os.path.join(path, f) for f in files]
            if full_files:
                output.update(full_files)

        return output


class SetUtils(object):
    "Provides utility methods on sets"

    @staticmethod
    def match_patterns(search_set, pattern):
        "Return a new set containing elements from search_set that match the given regex pattern"
        log.info("Excluding files matching pattern '%s'" % pattern)
        matching_set = set()
        regex = re.compile(pattern, re.IGNORECASE)
        for item in search_set:
            if regex.match(item) is not None:
                matching_set.add(item)

        return matching_set


class StringUtils(object):
    "Utilities on strings"

    @staticmethod
    def get_random_string(length=32):
        return ''.join(random.choice(
            string.ascii_letters + string.digits) for x in range(length))


class S3Backend:
    """
    Backend to handle S3 upload/download (modified from bakthat)
    """
    def __init__(self, access_key, secret_key, bucket_name, s3_location):
        conn = boto.connect_s3(access_key, secret_key)

        try:
            self.bucket = conn.get_bucket(bucket_name)
        except S3ResponseError, e:
            if e.code == "NoSuchBucket":
                self.bucket = conn.create_bucket(bucket_name, location=s3_location)
            else:
                raise e

    def download(self, key_name):
        """
        Download a file

        @param string key_name - Key of the file to download
        """
        k = Key(self.bucket, key_name)

        encrypted_out = TemporaryFile()
        k.get_contents_to_file(encrypted_out)
        encrypted_out.seek(0)

        return encrypted_out

    def __progress_callback(self, complete, total):
        "Callback to display progress"
        percent = int(complete * 100.0 / total)
        log.info("Upload completion: {}%".format(percent))

    def upload(self, key_name, file_name, cb=True):
        """
        Upload a file to the bucket

        @param string key_name - Key of the file to upload
        """
        k = Key(self.bucket, key_name)
        k.encrypted = True
        upload_kwargs = {}
        if cb:
            upload_kwargs = dict(cb=self.__progress_callback, num_cb=10)
        k.set_contents_from_filename(file_name, **upload_kwargs)
        k.set_acl("private")

    def ls(self):
        "List all keys in the bucket"
        return [key.name for key in self.bucket.get_all_keys()]

    def delete(self, key_name):
        """
        Delete an object from the bucket

        @param string key_name - Key of the object to delete
        """
        k = Key(self.bucket, key_name)
        return self.bucket.delete_key(k)


class GlacierBackend:
    """
    Backend to handle Glacier upload/download (modified from bakthat)
    """
    def __init__(self, access_key, secret_key, vault_name, region_name):
        log.info("Connecting to Amazon Glacier...")
        conn = boto.connect_glacier(aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, region_name=region_name)
        log.info("Connection established.")

        log.info("Creating vault '%s' if it doesn't exist (nothing will be done if it does)" % vault_name)
        self.vault = conn.create_vault(vault_name)

    def upload(self, file_name):
        """
        Backup the file and return the archive ID.

        @param string file_name - Full path to the file to backup
        @return string - AWS archive ID for the file
        """
        log.info("Uploading file '%s' to Glacier" % file_name)
        return self.vault.concurrent_create_archive_from_file(file_name, '')

#    def backup_inventory(self):
#        """
#        Backup the local inventory from shelve as a json string to S3
#        """
#        with glacier_shelve() as d:
#            if not d.has_key("archives"):
#                d["archives"] = dict()
#
#            archives = d["archives"]
#
#        s3_bucket = S3Backend(self.conf).bucket
#        k = Key(s3_bucket)
#        k.key = self.backup_key
#
#        k.set_contents_from_string(json.dumps(archives))
#
#        k.set_acl("private")
#
#
#    def restore_inventory(self):
#        """
#        Restore inventory from S3 to local shelve
#        """
#        s3_bucket = S3Backend(self.conf).bucket
#        k = Key(s3_bucket)
#        k.key = self.backup_key
#
#        loaded_archives = json.loads(k.get_contents_as_string())
#
#        with glacier_shelve() as d:
#            if not d.has_key("archives"):
#                d["archives"] = dict()
#
#            archives = loaded_archives
#            d["archives"] = archives


#    def get_archive_id(self, filename):
#        """
#        Get the archive_id corresponding to the filename
#        """
#        with glacier_shelve() as d:
#            if not d.has_key("archives"):
#                d["archives"] = dict()
#
#            archives = d["archives"]
#
#            if filename in archives:
#                return archives[filename]
#
#        return None
#
#    def download(self, keyname):
#        """
#        Initiate a Job, check its status, and download the archive if it's completed.
#        """
#        archive_id = self.get_archive_id(keyname)
#        if not archive_id:
#            return
#
#        with glacier_shelve() as d:
#            if not d.has_key("jobs"):
#                d["jobs"] = dict()
#
#            jobs = d["jobs"]
#            job = None
#
#            if keyname in jobs:
#                # The job is already in shelve
#                job_id = jobs[keyname]
#                try:
#                    job = self.vault.get_job(job_id)
#                except UnexpectedHTTPResponseError: # Return a 404 if the job is no more available
#                    del job[keyname]
#
#            if not job:
#                # Job initialization
#                job = self.vault.retrieve_archive(archive_id)
#                jobs[keyname] = job.id
#                job_id = job.id
#
#            # Commiting changes in shelve
#            d["jobs"] = jobs
#
#        log.info("Job {action}: {status_code} ({creation_date}/{completion_date})".format(**job.__dict__))
#
#        if job.completed:
#            log.info("Downloading...")
#            encrypted_out = tempfile.TemporaryFile()
#            encrypted_out.write(job.get_output().read())
#            encrypted_out.seek(0)
#            return encrypted_out
#        else:
#            log.info("Not completed yet")
#            return None
#
#    def retrieve_inventory(self, jobid):
#        """
#        Initiate a job to retrieve Galcier inventory or output inventory
#        """
#        if jobid is None:
#            return self.vault.retrieve_inventory(sns_topic=None, description="Bakthat inventory job")
#        else:
#            return self.vault.get_job(jobid)
#
#    def retrieve_archive(self, archive_id, jobid):
#        """
#        Initiate a job to retrieve Galcier archive or download archive
#        """
#        if jobid is None:
#            return self.vault.retrieve_archive(archive_id, sns_topic=None, description='Retrieval job')
#        else:
#            return self.vault.get_job(jobid)
#
#
#    def ls(self):
#        with glacier_shelve() as d:
#            if not d.has_key("archives"):
#                d["archives"] = dict()
#
#            return d["archives"].keys()
#
#    def delete(self, keyname):
#        archive_id = self.get_archive_id(keyname)
#        if archive_id:
#            self.vault.delete_archive(archive_id)
#            with glacier_shelve() as d:
#                archives = d["archives"]
#
#                if keyname in archives:
#                    del archives[keyname]
#
#                d["archives"] = archives
#
#            self.backup_inventory()


class IceItException(Exception):
    "Base exception class"
    pass


class IceIt(object):
    def __init__(self, config_profile):
        self.config = Config(config_profile)
        try:
            self.encryptor = Encryptor(self.config.get('encryption', 'key_id'))
        except ConfigParser.NoSectionError:
            self.encryptor = Encryptor(None)

        self.catalogue = None           # Need to open it when need it because if there's no config we'll be in trouble

    def __open_catalogue(self):
        "Open the catalogue"
        if not self.catalogue:
            self.catalogue = Catalogue(self.config.get_catalogue_path())

    def __initialise_backends(self):
        "Connect to storage backends"
        access_key = self.config.get("aws", "access_key")
        secret_key = self.config.get("aws", "secret_key")
        vault_name = self.config.get("aws", "glacier_vault")
        region_name = self.config.get("aws", "glacier_region")

        # where files are stored long-term
        self.long_term_storage_backend = GlacierBackend(access_key, secret_key, vault_name, region_name)

        bucket_name = self.config.get("aws", "s3_bucket")
        s3_location = self.config.get("aws", "s3_location")

        # A backend for accessing files immediately. The catalogue will be backed up here.
        self.ha_storage_backend = S3Backend(access_key, secret_key, bucket_name, s3_location)


    def write_config_file(self, settings):
        return self.config.write_config_file(settings)

    def key_pair_exists(self):
        "Returns a boolean indicating whether a key pair already exists"
        return os.path.exists(self.config.get_public_key_path()) or os.path.exists(self.config.get_private_key_path())

    def generate_key_pair(self, key_type, length, options):
        "Generate a new key pair"
        return self.encryptor.generate_key_pair(key_type, length, options)

    def list_secret_keys(self):
        "List the secret keys"
        return self.encryptor.list_secret_keys()

    def set_key_id(self, key_id):
        "Set the ID of the key to use for encryption"
        return self.encryptor.set_key_id(key_id)

    def export_keys(self):
        "Export the key pair"
        return self.encryptor.export_keys(self.config.get_public_key_path(), self.config.get_private_key_path())

    def is_configured(self):
        "Return a boolean indicating whether the current config profile is valid and complete"
        return self.config.is_valid()

    def __encryption_enabled(self):
        """
        Returns a boolean indicating whether to encrypt files

        @return boolean True if we should encrypt files
        """
        return len(self.encryptor.get_key_id()) > 0

    def __trim_ineligible_files(self, potential_files):
        """
        Return the supplied set with all files that shouldn't be backed up removed.
        """
        # apply configured exclude patterns
        total_excluded = 0
        exclude_patterns = self.config.get('processing', 'exclude_patterns').split(',')
        for pattern in exclude_patterns:
            remove_set = SetUtils.match_patterns(potential_files, pattern)
            total_excluded += len(remove_set)
            potential_files -= remove_set

        log.info("%d files excluded by %d exclude patterns." % (total_excluded, len(exclude_patterns)))

        if len(potential_files) == 0:
            return potential_files

        self.__open_catalogue()

        eligible_files = copy(potential_files)

        for file_path in potential_files:
            catalogue_item = self.catalogue.get(file_path)
            if catalogue_item:
                catalogue_item = catalogue_item[0]
                # if the mtime hasn't changed, remove from eligible_files
                log.info("File %s is already in the catalogue. Checking for changes..." % file_path)
                current_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))

                if catalogue_item.file_mtime == current_mtime:
                    log.info("File has the same modification time as previous backup. Skipping.")
                    eligible_files -= set([file_path])
                    continue

                # if it has, hash the file and remove from eligible_files if the old and current hashes are the same
                log.info("File has a different modification time from previous backup. Checking hashes to confirm "
                         "modifications...")
                current_hash = self.__get_file_hash(file_path)

                if catalogue_item.source_hash == current_hash:
                    log.info("File hash matches hash of backed up file. File will NOT be backed up on this run.")
                    eligible_files -= set([file_path])
                    continue

        return eligible_files

    def __compress_file(self, input_file, output_dir):
        """
        Compress a file. A new temporary file will be created and the handle returned.

        @param string input_file - File to compress
        @param string output_dir - Directory to write compressed file to
        @return File The temporary File object where the input was compressed to
        """
        (output_handle, output_path) = mkstemp(dir=output_dir)
        log.info("Compressing file %s to %s" % (input_file, output_path))

        with BZ2File(output_path, 'w') as archive:
            with open(input_file, 'r') as file:
                while True:
                    data = file.read(1024*1024)
                    if not data:
                        break

                    archive.write(data)

        log.info("Compression finished.")

        return output_path

    def __get_file_hash(self, file_path):
        """
        Generate a hash of the named file
        """
        hash = hashlib.sha256()
        with open(file_path) as file:
            while True:
                data = file.read(1024*1024)
                if not data:
                    break

                hash.update(data)

        return hash.hexdigest()


    def __process_files(self, eligible_files):
        """
        Perform all necessary processing prior to initiating an upload to the file store, e.g. combine files that
        need archiving into archives, compress files that should be compressed, encrypt files as necessary and
        obfuscate file names.
        """
        temp_dir = mkdtemp('-iceit')

        # compile all disable_compression patterns
        disable_compression_regexes = []
        for pattern in self.config.get('processing', 'disable_compression_patterns').split(','):
            disable_compression_regexes.append(re.compile(pattern, re.IGNORECASE))

        for file_name in eligible_files:
            source_path = file_name
            existing_catalogue_item = self.catalogue.get(source_path)

            if self.config.getboolean('catalogue', 'store_source_file_hashes') is True:
                log.info("Generating hash of source file %s" % file_name)
                # get a hash of the input file so we know when we've restored a file that it has been successful
                source_file_hash = self.__get_file_hash(file_name)
                log.info("Source file SHA256 hash is %s" % source_file_hash)
            else:
                source_file_hash = None

            # compress files if they don't match any exclusion rules
            compress_file = True
            for regex in disable_compression_regexes:
                log.debug("Checking whether file %s matches regex %s" % (file_name, regex))
                if regex.match(file_name) is not None:
                    log.info("Skipping compression of %s" % file_name)
                    compress_file = False
                    break

            # compress file
            if compress_file:
                file_name = self.__compress_file(file_name, temp_dir)

            # encrypt file
            if self.__encryption_enabled():
                file_name = self.encryptor.encrypt(file_name, temp_dir)

            if self.config.getboolean('processing', 'obfuscate_file_names') is True:
                old_file_name = file_name
#@todo - add a loop here to make sure that the file name hasn't already been used
                file_name = os.path.join(temp_dir, StringUtils.get_random_string())

                # if the file is already in temp_dir, rename it
                if old_file_name.startswith(temp_dir):
                    log.info("Obfuscating file %s. Renaming to %s" % (old_file_name, os.path.basename(file_name)))
                    os.rename(old_file_name, file_name)
                else:
                    # otherwise create a symlink using the obfuscated name to the file to avoid having to copy it
                    os.symlink(old_file_name, file_name)

            log.info("Generating hash of final processed file %s" % file_name)
            final_file_hash = self.__get_file_hash(file_name)
            log.info("Processed file SHA256 hash is %s" % final_file_hash)

            # upload to storage backend
            aws_archive_id = self.long_term_storage_backend.upload(file_name)

            # delete the temporary file or symlink
            if file_name.startswith(temp_dir):
                log.info("Deleting temporary file/symlink %s" % file_name)
                # @todo - implement

            try:
                catalogue_item_id = existing_catalogue_item.id
            except AttributeError:
                catalogue_item_id = None

            # update the catalogue
            self.catalogue.add_item(item={
                'source_path': source_path,
                'aws_archive_id': aws_archive_id,
                'file_mtime': datetime.fromtimestamp(os.path.getmtime(source_path)),
                'source_hash': source_file_hash,
                'processed_hash': final_file_hash,
                'last_backed_up': datetime.now()
            }, id=catalogue_item_id)

        # remove temporary directory
        log.info("Deleting temporary directory %s" % temp_dir)
#        os.rmdir(temp_dir)


    def backup(self, paths, recursive):
        """
        Backup the given paths under the given config profile, optionally recursively.
        """
        self.__initialise_backends()

        potential_files = set()
        # find all files in the given paths and add to a set
        for path in  paths:
            log.info("Finding files in path %s (recursive=%s)" % (path, recursive))
            if os.path.isdir(path):
                file_finder = FileFinder(path, recursive)
                potential_files.update(file_finder.get_files())
            else:
                potential_files.update([path])
        log.info("%d files found in %d paths" % (len(potential_files), len(paths)))

        # remove ineligible files from the backup list, e.g. files that match exclusion patterns, files that have
        # been backed up previously and haven't since been modified, etc.
        eligible_files = self.__trim_ineligible_files(potential_files)
        # Perform all necessary processing to backup the file, e.g. compress files that should be compressed,
        # encrypt files as necessary, obfuscate file names and upload to storage backend.
        self.__process_files(eligible_files)

        # if all went well, save new catalogue to highly available storage backend (S3)
# @todo encrypt config file & catalogue and back up to S3 (we should keep a certain number of previous versions - allow this
# to be configured)


# CLI application

app = aaargh.App(description="Compress, encrypt, obfuscate and archive files to Amazon S3/Glacier.")

@app.cmd(help="Set AWS S3/Glacier credentials.")
@app.cmd_arg('profile', type=str, help="Configuration profile name. Configuration "
                                        "profiles allow you to back up different parts of "
                                        "your system using different settings.")
def configure(profile):
    "Prompt for AWS credentials and write to config file"
    settings = {
        "aws": {},
        "encryption": {}
    }

    settings['aws']['access_key'] = raw_input("AWS Access Key: ")
    settings['aws']["secret_key"] = raw_input("AWS Secret Key: ")

    s3_locations = [l for l in dir(Location) if not '_' in l]
    print "S3 settings: The list of your files along with any encryption keys will be stored in S3."
    settings['aws']["s3_location"] = raw_input("S3 location (possible values are %s): " % ', '.join(s3_locations))
    settings['aws']["s3_bucket"] = raw_input("S3 Bucket Name (will be created if it doesn't exist): ")

    glacier_regions = boto.glacier.regions()
    print "Your files will be backed up to Glacier."
    settings['aws']["glacier_region"] = raw_input("Glacier region (possible values are %s): " % ', '.join([r.name for r in glacier_regions]))
    settings['aws']["glacier_vault"] = raw_input("Glacier Vault Name (will be created if it doesn't exist): ")

    iceit = IceIt(profile)

    secret_keys = iceit.list_secret_keys()
    secret_key_id = "NEW"
    if secret_keys:
        # if there are keys, let the user select one
        valid_responses = ["NEW", "NONE"]
        print "Available GPG keys:"
        print "%s " % '\n'.join(["%s (%s)" % (k['keyid'], ', '.join(k['uids'])) for k in secret_keys])
        secret_key_id = raw_input("Enter a key ID to use for encryption, NONE to disable encryption, or NEW to create a new key pair: ")
        secret_key_id = secret_key_id.strip().upper()

        valid_responses += [k['keyid'] for k in secret_keys]
        if not secret_key_id in valid_responses:
            print "%s is not a valid response. Aborting."
            sys.exit(1)

    if secret_key_id == "NEW":
        # generate a new key pair
        print "We need some details to generate a new GPG key pair..."
        key_options = {}
        default_key_length = 2048
        key_length = raw_input("Key length (default=%s): " % default_key_length)
        if not key_length:
            key_length = default_key_length
        key_options['name_real'] = raw_input("Enter your name: ")
        key_options['name_email'] = raw_input("Enter your email address: ")
        key_options['name_comment'] = raw_input("Enter a comment to attach to the key: ")
        key = iceit.generate_key_pair(key_type="RSA", length=key_length, options=key_options)

        print "Generated key %s" % key

        secret_key_id = key

    if secret_key_id != "NONE":
        settings['encryption']['key_id'] = secret_key_id
        iceit.set_key_id(secret_key_id)

    iceit.write_config_file(settings)

    print "Config file written. Please edit it to change further options."

    print "Exporting encryption keys to allow them to be backed up."
    iceit.export_keys()

    print "For safety I'm going to back your encryption keys up onto S3."
    print "They will be added to a tar.bz2 archive and encrypted with GPG using symmetric encryption (i.e. a passphrase)."
    print "The security of your files depends on the strength of this passphrase. Make it long and difficult to guess!"

    skip_key_backup = False
    while skip_key_backup == False:
        symmetric_passphrase = getpass.getpass("Enter a passphrase to use to encrypt your encryption keys, or leave "
                                               "blank to skip (not recommended): ")
        symmetric_passphrase = symmetric_passphrase.strip()
        if not symmetric_passphrase:
            print "Are you sure you want to skip backing up your encryption keys?"
            confirm_skip_key_backup = raw_input("If your keys are lost there will be NO WAY to decrypt your files (y/N): ")
            confirm_skip_key_backup = confirm_skip_key_backup.strip()
            skip_key_backup = confirm_skip_key_backup.lower() == 'y'
        else:
            symmetric_passphrase_confirmation = getpass.getpass("Enter again to confirm: ")
            symmetric_passphrase_confirmation = symmetric_passphrase_confirmation.strip()

            if symmetric_passphrase != symmetric_passphrase_confirmation:
                print "Error - passwords don't match"
                continue

            print "Encrypting encryption keys and backing up to S3..."
            raise IceItException("Implement backup of encryption keys")

@app.cmd(help="Backup the given path(s) using the specified backup profile.")
@app.cmd_arg('profile', type=str, help="Configuration profile name. Configuration "
                                        "profiles allow you to back up different parts of "
                                        "your system using different settings.")
@app.cmd_arg('-r', '--recursive', action="store_true", help="Backup directories recursively")
@app.cmd_arg('paths', type=str, nargs="+", help="Directories/files to backup")
def backup(profile, recursive, paths):
    iceit = IceIt(profile)
    if not iceit.is_configured():
        raise IceItException("Configuration profile '%s' doesn't exist or is corrupt." % profile)

    iceit.backup(paths, recursive)


if __name__ == '__main__':
    app.run()