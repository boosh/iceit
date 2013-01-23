#!/bin/env python

# Put your files on ice. Compress, encrypt, obfuscate and archive on Amazon Glacier.

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

log = logging.getLogger(__name__)

if not log.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

class Config(object):
    "Manages the application configuration"
    def __init__(self, config_dir=os.path.expanduser("~/.iceit")):
        self.config_dir = config_dir
        self.config = ConfigParser.SafeConfigParser()
        self.config.read(self.get_config_file_path())

    def get_config_file_path(self):
        "Return the path to the config file"
        return os.path.join(self.config_dir, 'iceit.conf')

    def get_public_key_path(self):
        "Return the path to the public key file"
        return os.path.join(self.config_dir, 'public.key')

    def get_private_key_path(self):
        "Return the path to the private key file"
        return os.path.join(self.config_dir, 'private.key')

    def write_config_file(self, settings):
        """
        Create default config.

        @param settings - dict containing AWS credentials
        """
        if not os.path.isdir(self.config_dir):
            os.mkdir(self.config_dir)

        if not self.config.has_section('aws'):
            self.config.add_section("aws")

        self.config.set("aws", "access_key", settings['aws']['access_key'])
        self.config.set("aws", "secret_key", settings['aws']['secret_key'])
        self.config.set("aws", "s3_location", settings['aws']['s3_location'])
        self.config.set("aws", "s3_bucket", settings['aws']['s3_bucket'])
        self.config.set("aws", "glacier_region", settings['aws']['glacier_region'])
        self.config.set("aws", "glacier_vault", settings['aws']['glacier_vault'])

        # default config values
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

        self.config.write(open(self.get_config_file_path(), "w"))

        log.info("Config written to %s" % self.get_config_file_path())


class Encryptor(object):
    """
    All crypto-related methods.
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


class IceItException(Exception):
    "Base exception class"
    pass


class IceIt(object):
    def __init__(self, config=None, encryptor=None):
        self.config = config or Config()
        self.encryptor = encryptor or Encryptor()

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

# CLI application

app = aaargh.App(description="Compress, encrypt, obfuscate and archive files to Amazon S3/Glacier.")

@app.cmd(help="Set AWS S3/Glacier credentials.")
def configure():
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

    iceit = IceIt()
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

if __name__ == '__main__':
    app.run()