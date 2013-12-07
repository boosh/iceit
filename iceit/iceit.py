import ConfigParser
from copy import copy
from datetime import datetime
import logging
import os
import random
import re
import tarfile
from tempfile import mkstemp, mkdtemp
from time import strftime

from .catalogue import Catalogue
from .crypto import Encryptor
from .utils import SetUtils, StringUtils, FileFinder, FileUtils
from .backends import GlacierBackend, S3Backend

# Put your files on ice. Compress, encrypt, obfuscate and archive them on Amazon Glacier.
#
# Inspired by duply/duplicity and bakthat.
#
# @todo - Allow files larger than a certain size to be split into pieces
# @todo - Implement a restore command. It should allow the version to be specified by backup date, e.g.
#         iceit.py restore default /full/or/partial/file/name@yyyy-mm-dd_HH:MM:SS
#         This will restore a specific version. By default the most recent will be restored.
#         Specifying file names in this way, we'll display all matching files in a numbered list, and the user
#         can select a number to show which file they want to restore.
#         Also allow an output path to be specified.
# @todo - An aggressive dedupe mode that compares candidate files by hashes in the db instead of looking at
#         file name

log = logging.getLogger(__name__)

if not log.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

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
        self.config.set("aws", "sns_topic_arn", settings['aws']['sns_topic_arn'])

        # default config values
        if not self.config.has_section('catalogue'):
            self.config.add_section('catalogue')
            # name of the sqlite3 database file (under the config directory) to use as the catalogue
            self.config.set('catalogue', 'name', 'catalogue.db')
            # whether to store hashes of the source files in the catalogue
            self.config.set('catalogue', 'store_source_file_hashes', 'true')
            # maximum number of backups to preserve on S3
            self.config.set('catalogue', 'num_catalogue_config_backups_to_keep', '14')

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

        with open(self.get_config_file_path(), "w") as file:
            self.config.write(file)

        log.info("Config written to %s" % self.get_config_file_path())


class IceIt(object):
    def __init__(self, config_profile):
        self.config_profile = config_profile
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
        log.debug("Initialising backends...")
        access_key = self.config.get("aws", "access_key")
        secret_key = self.config.get("aws", "secret_key")
        vault_name = self.config.get("aws", "glacier_vault")
        region_name = self.config.get("aws", "glacier_region")

        # where files are stored long-term
        self.long_term_storage_backend = GlacierBackend(access_key, secret_key, vault_name, region_name)
        log.debug("Connected to Glacier")

        bucket_name = self.config.get("aws", "s3_bucket")
        s3_location = self.config.get("aws", "s3_location")

        # A backend for accessing files immediately. The catalogue will be backed up here.
        self.ha_storage_backend = S3Backend(access_key, secret_key, bucket_name, s3_location)
        log.debug("Connected to S3")

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
        self.encryptor.key_id = key_id

    def export_keys(self):
        "Export the key pair"
        return self.encryptor.export_keys(self.config.get_public_key_path(), self.config.get_private_key_path())

    def backup_encryption_keys(self, symmetric_passphrase):
        """
        Backup encryption keys to S3. Keys will be combined into a tar.bz2 archive then encrypted with
        GPG using symmetric encryption before being uploaded to S3.

        @param string symmetric_passphrase - The passphrase to use to encrypt the archive.
        """
        self.__initialise_backends()
        (file_handle, archive_path) = mkstemp()
        tar_archive = tarfile.open(name=archive_path, mode='w:bz2')
        public_key_path = self.config.get_public_key_path()
        log.info("Adding public key '%s' to key archive '%s'" % (public_key_path, archive_path))
        tar_archive.add(public_key_path)

        private_key_path = self.config.get_private_key_path()
        log.info("Adding private key '%s' to key archive '%s'" % (private_key_path, archive_path))
        tar_archive.add(private_key_path)
        log.info("Closing key archive")
        tar_archive.close()

        # encrypt with GPG
        encrypted_file_name = self.encryptor.encrypt_symmetric(passphrase=symmetric_passphrase, input_file=archive_path,
            output_dir=os.path.dirname(archive_path))

        # upload to S3
        self.ha_storage_backend.upload('iceit-keys-%s-%s' % (self.config_profile, strftime("%Y%m%d_%H%M%S")), encrypted_file_name)

        # Delete archives
        log.info("Deleting unencrypted temporary key archive %s" % archive_path)
        os.unlink(archive_path)

        log.info("Deleting encrypted temporary key archive %s" % encrypted_file_name)
        os.unlink(encrypted_file_name)

    def __backup_catalogue_and_config(self):
        """
        Backup catalogue and config file to S3. Catalogue and config will be combined into a tar.bz2 archive then
        encrypted with GPG before being uploaded to S3.
        """
        self.__initialise_backends()
        (file_handle, archive_path) = mkstemp()
        tar_archive = tarfile.open(name=archive_path, mode='w:bz2')
        catalogue_path = self.config.get_catalogue_path()
        log.info("Adding catalogue '%s' to config backup archive '%s'" % (catalogue_path, archive_path))
        tar_archive.add(catalogue_path)

        config_path = self.config.get_config_file_path()
        log.info("Adding config file '%s' to config backup archive '%s'" % (config_path, archive_path))
        tar_archive.add(config_path)
        log.info("Closing config backup archive")
        tar_archive.close()

        # encrypt with GPG
        encrypted_file_name = self.encryptor.encrypt(input_file=archive_path, output_dir=os.path.dirname(archive_path))

        # upload to S3
        self.ha_storage_backend.upload('iceit-catalogue-%s-%s' % (self.config_profile, strftime("%Y%m%d_%H%M%S")), encrypted_file_name)

        # Delete archives
        log.info("Deleting unencrypted config backup archive %s" % archive_path)
        os.unlink(archive_path)

        log.info("Deleting encrypted temporary config backup archive %s" % encrypted_file_name)
        os.unlink(encrypted_file_name)

    def is_configured(self):
        "Return a boolean indicating whether the current config profile is valid and complete"
        return self.config.is_valid()

    def encryption_enabled(self):
        """
        Returns a boolean indicating whether to encrypt files

        @return boolean True if we should encrypt files
        """
        return len(self.encryptor.key_id) > 0

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

        eligible_files = copy(potential_files)

        for file_path in potential_files:
            catalogue_items = self.catalogue.get(file_path)
            for catalogue_item in catalogue_items:
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
                current_hash = FileUtils.get_file_hash(file_path)
                if catalogue_item.source_hash == current_hash:
                    log.info("File hash matches hash of backed up file. File will NOT be backed up on this run.")
                    eligible_files -= set([file_path])
                    continue

        return eligible_files

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

        total_files_to_backup = len(eligible_files)
        files_backed_up = 0

        # paranoia - shuffle the order of the eligible_files so that no-one could know which encrypted file
        # corresponds to which uploaded file even if they had a directory listing of files that were uploaded
        # and could inspect timestamps in Glacier (if all files were the same size)
        eligible_files_list = list(eligible_files)
        random.shuffle(eligible_files_list)

        for file_name in eligible_files_list:
            source_path = file_name
            existing_catalogue_item = self.catalogue.get(source_path)

            if self.config.getboolean('catalogue', 'store_source_file_hashes') is True:
                log.info("Generating hash of source file %s" % file_name)
                # get a hash of the input file so we know when we've restored a file that it has been successful
                source_file_hash = FileUtils.get_file_hash(file_name)
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
                file_name = FileUtils.compress_file(file_name, temp_dir)

            # encrypt file
            if self.encryption_enabled():
                unencrypted_file_name = file_name
                file_name = self.encryptor.encrypt(file_name, temp_dir)

            if self.config.getboolean('processing', 'obfuscate_file_names') is True:
                old_file_name = file_name

                file_name = os.path.join(temp_dir, StringUtils.get_random_string())

                # if the file is already in temp_dir, rename it
                if old_file_name.startswith(temp_dir):
                    log.info("Obfuscating file %s. Renaming to %s" % (old_file_name, os.path.basename(file_name)))
                    os.rename(old_file_name, file_name)
                else:
                    # otherwise create a symlink using the obfuscated name to the file to avoid having to copy it
                    os.symlink(old_file_name, file_name)

            log.info("Generating hash of final processed file %s" % file_name)
            final_file_hash = FileUtils.get_file_hash(file_name)
            log.info("Processed file SHA256 hash is %s" % final_file_hash)

            # upload to storage backend
# @todo split large files into smaller chunks and process them all together. They should be separately encrypted and
# @todo hashed so we know when downloading that each piece is correct
# @todo - confirm that uploads where errors were caught did actually upload correctly
            aws_archive_id = self.long_term_storage_backend.upload(file_name)

            # delete the temporary file or symlink
            if file_name.startswith(temp_dir):
                log.info("Deleting temporary file/symlink %s" % file_name)
                os.unlink(file_name)
                if unencrypted_file_name.startswith(temp_dir):
                    log.info("Deleting unencrypted file/symlink %s" % unencrypted_file_name)
                    os.unlink(unencrypted_file_name)

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

            files_backed_up += 1
            log.info("Backed up %d of %d files" % (files_backed_up, total_files_to_backup))

        # remove temporary directory
        log.info("All files processed. Deleting temporary directory %s" % temp_dir)
        os.rmdir(temp_dir)


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

        try:
            self.__open_catalogue()

            # remove ineligible files from the backup list, e.g. files that match exclusion patterns, files that have
            # been backed up previously and haven't since been modified, etc.
            eligible_files = self.__trim_ineligible_files(potential_files)

            if len(eligible_files) > 0:
                # Perform all necessary processing to backup the file, e.g. compress files that should be compressed,
                # encrypt files as necessary, obfuscate file names and upload to storage backend.
                self.__process_files(eligible_files)

                # if all went well, save new catalogue to highly available storage backend (S3)
                self.__backup_catalogue_and_config()

                #@todo - purge old config backups
            else:
                log.info("No files need backing up.")
        except Exception as e:
            log.exception("Caught an exception. Closing catalogue.")
        finally:
            self.catalogue.close()
