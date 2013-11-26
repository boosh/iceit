#!/usr/bin/env python

import aaargh
import logging
import getpass
import sys
import os
import boto
from boto.s3.connection import Location

# add the parent dir to the path so it can load the main modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

log = logging.getLogger(__name__)

if not log.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

from iceit.iceit import IceIt
from iceit.exceptions import IceItException


# CLI application

app = aaargh.App(description="Compress, encrypt, obfuscate and archive files to Amazon S3/Glacier.")

@app.cmd(help="Set AWS S3/Glacier credentials.")
@app.cmd_arg('profile', type=str, help="Configuration profile name. Configuration "
                                       "profiles allow you to back up different parts of "
                                       "your system using different settings.")
def configure(profile):
    "Prompt for AWS credentials and write to config file"
    if ' ' in profile:
        raise IceItException("Profile names may not contain spaces")

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

    settings['aws']['sns_topic_arn'] = raw_input("SNS topic ARN to which you want to job notifications sending "
                                                 "(leave blank to disable): ")

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

    if iceit.encryption_enabled():
        print "Exporting encryption keys to allow them to be backed up."
        iceit.export_keys()

        backup_keys(profile)

    print "Configuration complete"


@app.cmd(help="Backup your encryption keys to S3.")
@app.cmd_arg('profile', type=str, help="Configuration profile name. Configuration "
                                       "profiles allow you to back up different parts of "
                                       "your system using different settings.")
def backup_keys(profile):
    iceit = IceIt(profile)

    if not iceit.encryption_enabled():
        print "No encryption keys are configured. Aborting."

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

            iceit.backup_encryption_keys(symmetric_passphrase)
            break


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