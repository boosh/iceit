import ConfigParser
from copy import copy
from datetime import datetime
import os
import random
import re
import tarfile
import shutil
from tempfile import mkstemp, mkdtemp
from time import strftime

from .config import Config
from .catalogue import Catalogue
from .crypto import Encryptor
from .utils import SetUtils, StringUtils, FileFinder, FileUtils
from .backends import GlacierBackend, S3Backend
from .log import get_logger

log = get_logger(__name__)

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
        self.glacier_backend = GlacierBackend(access_key, secret_key, vault_name, region_name)
        log.debug("Connected to Glacier")

        bucket_name = self.config.get("aws", "s3_bucket")
        s3_location = self.config.get("aws", "s3_location")

        # A backend for accessing files immediately. The catalogue will be backed up here.
        self.s3_backend = S3Backend(access_key, secret_key, bucket_name, s3_location)
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
        self.s3_backend.upload('%s%s-%s' % (self.config.get('aws', 's3_key_prefix'),
                                            self.config_profile, strftime("%Y%m%d_%H%M%S")),
                               encrypted_file_name)

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
        tar_archive.add(name=catalogue_path, arcname=os.path.basename(catalogue_path))

        config_path = self.config.get_config_file_path()
        log.info("Adding config file '%s' to config backup archive '%s'" % (config_path, archive_path))
        tar_archive.add(name=config_path, arcname=os.path.basename(config_path))
        log.info("Closing config backup archive")
        tar_archive.close()

        # encrypt with GPG
        encrypted_file_name = self.encryptor.encrypt(input_file=archive_path, output_dir=os.path.dirname(archive_path))

        # upload to S3
        self.s3_backend.upload('%s%s-%s' % (self.config.get('aws', 's3_catalogue_prefix'),
                                            self.config_profile, strftime("%Y%m%d_%H%M%S")),
                               encrypted_file_name)

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
            aws_archive_id = self.glacier_backend.upload(file_name)

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

    def list_catalogues(self):
        """
        List catalogues backed up to S3
        """
        self.__initialise_backends()

        catalogues = [i for i in self.s3_backend.ls() if i['name'].startswith(self.config.get('aws', 's3_catalogue_prefix'))]

        return sorted(catalogues)

    def restore_catalogue(self, name):
        """
        Restore a particular catalogue and rename any existing one
        """
        self.__initialise_backends()

        log.debug("Creating temporary dir to download archive to")
        temp_dir = mkdtemp(prefix='iceit-catalogue-restore')
        log.debug("Created %s" % temp_dir)

        (handle, temp_file_path) = mkstemp(prefix='iceit-catalogue-', dir=temp_dir)

        log.info("Retrieving file '%s' to temporary path '%s'" % (name, temp_file_path))
        self.s3_backend.get_to_file(name, temp_file_path)

        log.info("Decrypting retrieved archive")
        decrypted_archive = self.encryptor.decrypt(input_file=temp_file_path, output_dir=os.path.dirname(temp_file_path))

        log.info("Extracting decrypted archive")

        if not tarfile.is_tarfile(decrypted_archive):
            raise RuntimeError("Error: Unable to read tar file '%s'" % decrypted_archive)

        tar_archive = tarfile.open(name=decrypted_archive, mode='r:bz2')
        log.info("Extracting contents of archive to '%s'" % temp_dir)
        tar_archive.extractall(path=temp_dir)
        tar_archive.close()

        log.info("Deleting downloaded archive '%s'" % decrypted_archive)
        os.unlink(decrypted_archive)

        existing_catalogue_path = self.config.get_catalogue_path()

        if os.path.exists(existing_catalogue_path):
            new_catalogue_path = "%s-%s" % (existing_catalogue_path, strftime("%Y%m%d%H%M%S"))
            log.info("Renaming existing catalogue from %s to %s" % (existing_catalogue_path, new_catalogue_path))

            os.rename(existing_catalogue_path, new_catalogue_path)

        restored_catalogue_path = os.path.join(temp_dir, self.config.get('catalogue', 'name'))

        log.info("Moving downloaded catalogue from '%s' to '%s'" % (restored_catalogue_path,
                                                                    existing_catalogue_path))
        os.rename(restored_catalogue_path, existing_catalogue_path)

        log.info("Deleting temporary directory '%s'" % temp_dir)
        shutil.rmtree(temp_dir)

    def list_keys(self):
        """
        List keys backed up to S3
        """
        self.__initialise_backends()

        keys = [i for i in self.s3_backend.ls() if i['name'].startswith(self.config.get('aws', 's3_key_prefix'))]

        return sorted(keys)

    def find_in_catalogue(self, filter):
        """
        Find entries in the catalogue that match the given filter

        @param filter: Optional filter to apply to file names

        :return: list of matching entries
        """
        try:
            self.__open_catalogue()

            items = self.catalogue.find_item(filter)

            return items
        except Exception as e:
            #@todo rethrow exception
            log.exception("Caught an exception. Closing catalogue.")
        finally:
            self.catalogue.close()
