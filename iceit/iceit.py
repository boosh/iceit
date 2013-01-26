#!/bin/env python

# Put your files on ice. Compress, encrypt, obfuscate and archive them on Amazon Glacier.
#
# Inspired by duply/duplicity and bakthat.

import aaargh
import boto.glacier
import boto.s3
from boto.s3.connection import Location
import ConfigParser
import getpass
import logging
import os
from Crypto.PublicKey import RSA
from Crypto import Random
import random
import re
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, DateTime, select
import string

log = logging.getLogger(__name__)

if not log.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

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
            Column('path', String),
            Column('obfuscated_name', String),
            Column('file_mtime', DateTime),
            Column('hash', String),
            Column('last_backed_up', DateTime)
        )

        metadata.create_all(self.engine)
        log.info("DB tables created...")

    def get(self, file_path):
        "Get a file entry or return an empty list if not found"
        file_table = self.tables['files']
        query = select([file_table], file_table.c.path==file_path)
        result = self.conn.execute(query)

        rows = result.fetchall()

        print rows


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

        if not self.config.has_section('encryption'):
            self.config.add_section('encryption')
            # Whether to encrypt files or not
            self.config.set('encryption', 'encrypt_files', 'True')
            # path to public key
            self.config.set('encryption', 'public_key_path', self.get_public_key_path())
            # path to private key
            self.config.set('encryption', 'private_key_path', self.get_private_key_path())

        if not self.config.has_section('processing'):
            self.config.add_section('processing')
            # files whose extensions match the following regexes will not be compressed
            self.config.set('processing', 'disable_compression_extensions', 'avi,mp4,mpe?g,jpe?g,mp3,bz2,gz(ip)?')
            # Whether to create a single archive per directory (True), or to process files individually
            self.config.set('processing', 'create_one_archive_per_directory', 'true')
            # The minimum number of files to add to an archive when creating one per directory automatically
            self.config.set('processing', 'min_files_per_directory_archive', '2')
            # Whether to obfuscate file names before uploading them
            self.config.set('processing', 'obfuscate_file_names', 'true')
            # File patterns (as reg exes) to exclude from backing up. Separate multiple with commas.
            self.config.set('processing', 'exclude_patterns', '^.*/desktop\.ini$')

        self.config.write(open(self.get_config_file_path(), "w"))

        log.info("Config written to %s" % self.get_config_file_path())


class Encryptor(object):
    """
    All crypto-related methods.

    @todo - replace with gnupg
    """
    def generate_key_pair(self, length=2048, passphrase=None):
        """
        Generates an RSA key pair.
        """
        log.info("Generating RSA key pair")
        self.key = RSA.generate(length, Random.new().read)
        log.info("Key generated")

    def export_keys(self, public_key_path, private_key_path, passphrase):
        """
        Export the public and private keys, with the private key protected by the given passphrase.
        """
        log.info("Writing public key to %s" % public_key_path)
        with open(public_key_path, 'w') as pub_key_file:
            pub_key_file.write(self.key.publickey().exportKey())
        log.info("Public key written.")

        log.info("Writing private key to %s" % private_key_path)
        with open(private_key_path, 'w') as private_key_file:
            private_key_file.write(self.key.exportKey('PEM', passphrase))
        log.info("Private key written.")


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
        regex = re.compile(pattern)
        for item in search_set:
            if regex.match(item) != None:
                matching_set.add(item)

        return matching_set


class StringUtils(object):
    "Utilities on strings"

    @staticmethod
    def get_random_string(length=32):
        return ''.join(random.choice(
            string.ascii_letters + string.digits) for x in range(length))


class IceItException(Exception):
    "Base exception class"
    pass


class IceIt(object):
    def __init__(self, config_profile):
        self.config = Config(config_profile)
        self.encryptor = Encryptor()
        self.catalogue = None           # Need to open it when need it because if there's no config we'll be in trouble

    def __open_catalogue(self):
        "Open the catalogue"
        if not self.catalogue:
            self.catalogue = Catalogue(self.config.get_catalogue_path())

    def write_config_file(self, settings):
        return self.config.write_config_file(settings)

    def key_pair_exists(self):
        "Returns a boolean indicating whether a key pair already exists"
        return os.path.exists(self.config.get_public_key_path()) or os.path.exists(self.config.get_private_key_path())

    def generate_key_pair(self):
        "Generate a new key pair"
        return self.encryptor.generate_key_pair()

    def export_keys(self, passphrase):
        "Export the key pair using the given passphrase to secure the private key"
        return self.encryptor.export_keys(self.config.get_public_key_path(), self.config.get_private_key_path(), passphrase)

    def is_configured(self):
        "Return a boolean indicating whether the current config profile is valid and complete"
        return self.config.is_valid()

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
            return

        self.__open_catalogue()

        for file in potential_files:
            existing_backups = self.catalogue.get(file)
            if len(existing_backups):
                # if the mtime hasn't changed, remove from potential_files

                # if it has, hash the file and remove from potential_files if the old and current hashes are the same

# @todo - complete this once there is data in the catalogue
                pass

    def __process_files(self, eligible_files):
        """
        Perform all necessary processing prior to initiating an upload to the file store, e.g. combine files that
        need archiving into archives, compress files that should be compressed, encrypt files as necessary and
        obfuscate file names.
        """
        # iterate over the file list building a dictionary of metadata about whether the file should be added to
        # an archive, compressed, encrypted, etc.
        for file in eligible_files:
# @todo - implement this and create a new data structure

        for file, metadata in new_data_structure_from_the_above_step:
# @todo - implement this
            # combine files into archives as necessary

            # compress files

            # encrypt files

            obfuscated_name = StringUtils.get_random_string()
            # update the catalogue, but don't commit until all files are processed (although uploading may
            # subsequently fail)



    def backup(self, paths, recursive):
        """
        Backup the given paths under the given config profile, optionally recursively.
        """
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
        # Perform all necessary processing prior to initiating an upload to the file store, e.g. combine files that
        # need archiving into archives, compress files that should be compressed, encrypt files
        # as necessary and obfuscate file names.
        self.__process_files(eligible_files)
        # upload to storage backend
        # if all went well, save new catalogue to highly available storage backend

# CLI application

app = aaargh.App(description="Compress, encrypt, obfuscate and archive files to Amazon S3/Glacier.")

@app.cmd(help="Set AWS S3/Glacier credentials.")
@app.cmd_arg('profile', type=str, help="Configuration profile name. Configuration "
                                        "profiles allow you to back up different parts of "
                                        "your system using different settings.")
def configure(profile):
    "Prompt for AWS credentials and write to config file"
    settings = {"aws": {}}

    settings['aws']['access_key'] = raw_input("AWS Access Key: ")
    settings['aws']["secret_key"] = raw_input("AWS Secret Key: ")

    s3_locations = [l for l in dir(Location) if not '_' in l]
    print "S3 settings: The list of your files along with any encryption keys will be stored in S3."
    settings['aws']["s3_location"] = raw_input("S3 location (possible values are %s): " % ', '.join(s3_locations))
    settings['aws']["s3_bucket"] = raw_input("S3 Bucket Name: ")

    glacier_regions = boto.glacier.regions()
    print "Your files will be backed up to Glacier."
    settings['aws']["glacier_region"] = raw_input("Glacier region (possible values are %s): " % ', '.join([r.name for r in glacier_regions]))
    settings['aws']["glacier_vault"] = raw_input("Glacier Vault Name: ")

    iceit = IceIt(profile)
    iceit.write_config_file(settings)

    print "Config file written. Please edit it to change further options."

    if not iceit.key_pair_exists():
        iceit.generate_key_pair()
        print "\nSecure your private key with a passphrase."
        print "IMPORTANT: If you forget this passphrase there will be no way to recover your files! "
        passphrase_1 = getpass.getpass("Enter a strong passphrase to secure your private key: ")
        passphrase_2 = getpass.getpass("Enter again to confirm: ")
        if passphrase_1 != passphrase_2:
            raise IceItException("Passphrases don't match.")
        iceit.export_keys(passphrase_1)

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