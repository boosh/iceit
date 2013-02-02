IceIt - Put your files on ice
=============================
IceIt lets you back up your files to Amazon Glacier. It can:

  * Optionally compress certain file types prior to backing up
  * Encrypt your files before backing up
  * Obfuscate file names so nobody will be able to know what you have uploaded
  * Support multiple backup profiles, each containing different settings
  * Compare files that have changed in your backup directories and only upload changed/new files
  * Encrypt & backup all config files to S3 for safety

IceIt also maintains an sqlite database containing information about the files that have been backed up. This
is especially important when file names have been obfuscated because it contains information about the original
file name, the obfuscated file name and various hashes that confirm a file's integrity upon decryption.

Because this catalogue is critical, it is automatically encrypted and backed up to S3. Without it while you will
technically be able to recover your files, you will have to manually examine them and rename them to their original
names.

Requirements
------------

  * python
  * gpg
  * Amazon Web Services account for Glacier and S3

Installation under virtualenv
-----------------------------
Assuming you have virtualenv installed, do the following:

  * virtualenv venv
  * pip install -r requirements.txt

Usage
-----
If you installed IceIt in a virtualenv, you'll need to activate the virtualenv by running:

`source ./venv/bin/activate`

Alternatively execute it by passing the full path to the python interpreter inside the virtualenv, e.g.

`/path/to/venv/bin/python /path/to/iceit.py`

Configuration
-------------
Before you can perform backups, you must configure Iceit. IceIt stores groups of settings in a configuration profile.
To create a new profile, run:

`iceit configure PROFILE_NAME` - you can replace PROFILE_NAME with whatever you want to call this profile.

You will be prompted for various settings, such as your AWS account credentials and GPG encryption key ID. IceIt
will then create a new subdirectory under ~/.iceit with the profile name, and write a config file. It will also
export your GPG keys into that directory so they can be backed up.

Note: When selecting a GPG key ID, choose a key without a passphrase. IceIt encrypts and signs files before backing
them up, and signing requires the private key. If it is protected by a passphrase, it will not be possible for
IceIt to prompt you for it, or to run IceIt by cron.

Running backups
---------------
Once configured, IceIt can be made to perform backups by invoking it as follows:

`iceit backup PROFILE_NAME FILES...` where PROFILE_NAME is the name of a backup profile, and FILES... is lists
of files or directories to backup.