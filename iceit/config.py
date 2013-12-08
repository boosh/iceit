import os
import ConfigParser
from .log import get_logger

log = get_logger(__name__)


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

        if not self.config.has_option('aws', 's3_catalogue_prefix'):
            self.config.set("aws", "s3_catalogue_prefix", 'iceit-catalogue-')
        else:
            self.config.set("aws", "s3_catalogue_prefix", settings['aws']['s3_catalogue_prefix'])

        if not self.config.has_option('aws', 's3_catalogue_prefix'):
            self.config.set("aws", "s3_key_prefix", 'iceit-keys-')
        else:
            self.config.set("aws", "s3_key_prefix", settings['aws']['s3_key_prefix'])

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

