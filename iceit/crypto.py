import os
import gnupg
import logging
import pipes

from .exceptions import IceItException

log = logging.getLogger(__name__)

if not log.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

class Encryptor(object):
    """
    All crypto-related methods.
    """
    def __init__(self, key_id):
        """
        @param string key_id - The ID of the key to use for encryption
        """
        self.gpg = gnupg.GPG()
        self.key_id = key_id

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

        @return The ID of the new key
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
        if not self.key_id:
            raise IceItException("Can't encrypt files. Set the key ID first.")

        encrypted_file_name = os.path.join(output_dir, "%s%s" % (os.path.basename(input_file), output_extension))
        encrypted_file_name = pipes.quote(encrypted_file_name)

        if not os.path.exists(input_file):
            raise IceItException("Can't encrypt non-existent file '%s'" % input_file)

        log.info("Encrypting %s to %s" % (input_file, encrypted_file_name))
        with open(input_file, 'r') as file:
            self.gpg.encrypt_file(file, self.key_id, sign=self.key_id, armor=False, output=encrypted_file_name)

        if not os.path.exists(encrypted_file_name) or os.path.getsize(encrypted_file_name) == 0:
            raise IceItException("Failed to encrypt file. Perhaps you specified a key that needs a passphrase?")

        log.info("Encryption complete.")
        return encrypted_file_name

    def encrypt_symmetric(self, passphrase, input_file, output_dir, output_extension='.gpg'):
        """
        Encrypt and sign a file using symmetric encryption. File will be signed with the current key.

        @param string passphrase - The passphrase to use
        @param string input_file - The file to encrypt.
        @param string output_dir - The directory to write the encrypted file to.
        @param string output_extension - An extension to append to the file
        """
        if not os.path.exists(input_file):
            raise IceItException("Can't encrypt non-existent file '%s'" % input_file)

        encrypted_file_name = os.path.join(output_dir, "%s%s" % (os.path.basename(input_file), output_extension))
        encrypted_file_name = encrypted_file_name.replace('`', "'")

        log.info("Encrypting %s to %s using symmetric encryption" % (input_file, encrypted_file_name))
        with open(input_file) as file:
            self.gpg.encrypt_file(file, recipients=None, sign=self.key_id, armor=False, output=encrypted_file_name,
                symmetric=True, passphrase=passphrase)

        return encrypted_file_name

    def decrypt(self, input_file, output_dir):
        """
        Decrypt the given file using the private key.

        @param string input_file - The file to decrypt.
        @param string output_dir - The directory to write the decrypted file to.
        """
        if not self.key_id:
            raise IceItException("Can't decrypt files. Set the key ID first.")

        dest_file_name = os.path.join(output_dir, os.path.basename(input_file))
        dest_file_name = pipes.quote(dest_file_name)

        if not os.path.exists(input_file):
            raise IceItException("Can't decrypt non-existent file '%s'" % input_file)

        log.info("Decrypting %s to %s" % (input_file, dest_file_name))
        with open(input_file, 'rb') as file:
            # signature is automatically verified I think
            result = self.gpg.decrypt_file(file, output=dest_file_name)

        if not os.path.exists(dest_file_name) or os.path.getsize(dest_file_name) == 0:
            raise IceItException("Failed to decrypt file. Perhaps you specified a key that needs a passphrase?")

        log.info("Encryption complete.")
        return dest_file_name