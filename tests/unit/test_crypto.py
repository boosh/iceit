import unittest
from mock import patch, Mock, mock_open

from iceit.crypto import Encryptor
from iceit.exceptions import IceItException

class TestEncryptor(unittest.TestCase):
    """
    Test the Encryptor class
    """
    def test_init(self):
        """
        Test Encryptor init
        """
        fake_key_id = 'a-fake-key'
        encryptor = Encryptor(fake_key_id)

        self.assertEqual(encryptor.key_id, fake_key_id)
        return encryptor

    def test_list_keys(self):
        """
        Test listing keys makes the expected call
        """
        with patch('iceit.crypto.gnupg.GPG') as mock_gpg:
            mock_gpg.return_value = mock_gpg
            encryptor = self.test_init()
            encryptor.list_secret_keys()

            mock_gpg.list_keys.assert_called_once_with(True)

    def test_generate_key_pair(self):
        """
        Test generating key pairs makes the expected calls
        """
        with patch('iceit.crypto.gnupg.GPG') as mock_gpg:
            mock_key = Mock()
            mock_key.fingerprint = 'fake-fingerprint'
            mock_gpg.gen_key.return_value = mock_key

            mock_gpg.return_value = mock_gpg
            encryptor = self.test_init()
            fake_key = encryptor.generate_key_pair(key_type="RSA", length=4096, options={
                'name_real': 'Fake Name', 'name_email': 'fake@example.com', 'name_comment': 'Fake comment'})

            self.assertEqual(mock_gpg.gen_key_input.call_count, 1)
            self.assertEqual(fake_key, mock_key.fingerprint)

    def test_export_keys_success(self):
        """
        Test exporting keys works
        """
        mock_open_obj = mock_open()
        fake_public_key_path = 'fake-public-key-path'
        fake_private_key_path = 'fake-private-key-path'
        fake_public_key_string = 'my fake key string'
        fake_private_key_string = 'my fake private key string'

        def return_fake_key_data(key_id, private=False):
            if private:
                return fake_private_key_string
            else:
                return fake_public_key_string

        with patch('iceit.crypto.gnupg.GPG') as mock_gpg:
            mock_gpg.export_keys.side_effect = return_fake_key_data
            mock_gpg.return_value = mock_gpg
            with patch('iceit.crypto.open', mock_open_obj, create=True):
                with patch('os.path.getsize') as mock_getsize:
                    mock_getsize.return_value = 10
                    encryptor = self.test_init()

                    encryptor.export_keys(public_key_dest=fake_public_key_path, private_key_dest=fake_private_key_path)

        # assert the calls to write the public key
        (pub_name, pub_args, pub_kwargs) = mock_open_obj.mock_calls[0]
        self.assertEqual(pub_args[0], fake_public_key_path)
        self.assertEqual(pub_args[1], 'w')

        # assert the calls to write the public key data
        (pub_name, pub_args, pub_kwargs) = mock_open_obj.mock_calls[2]
        self.assertEqual(pub_args[0], fake_public_key_string)

        # assert the calls to write the private key
        (pub_name, pub_args, pub_kwargs) = mock_open_obj.mock_calls[4]
        self.assertEqual(pub_args[0], fake_private_key_path)
        self.assertEqual(pub_args[1], 'w')

        # assert the calls to write the private key data
        (pub_name, pub_args, pub_kwargs) = mock_open_obj.mock_calls[6]
        self.assertEqual(pub_args[0], fake_private_key_string)

    def test_export_keys_no_public_key_written(self):
        """
        Test exporting keys works
        """
        mock_open_obj = mock_open()
        fake_public_key_path = 'fake-public-key-path'
        fake_private_key_path = 'fake-private-key-path'

        with patch('iceit.crypto.gnupg.GPG') as mock_gpg:
            mock_gpg.return_value = mock_gpg
            with patch('iceit.crypto.open', mock_open_obj, create=True):
                with patch('os.path.getsize') as mock_getsize:
                    mock_getsize.return_value = 0
                    encryptor = self.test_init()

                    with self.assertRaises(IceItException):
                        encryptor.export_keys(public_key_dest=fake_public_key_path, private_key_dest=fake_private_key_path)

    def test_export_keys_no_private_key_written(self):
        """
        Test exporting keys works
        """
        mock_open_obj = mock_open()
        fake_public_key_path = 'fake-public-key-path'
        fake_private_key_path = 'fake-private-key-path'

        # file sizes get popped, so this will return 0 for the second call
        fake_file_sizes = [0, 10]

        with patch('iceit.crypto.gnupg.GPG') as mock_gpg:
            mock_gpg.return_value = mock_gpg
            with patch('iceit.crypto.open', mock_open_obj, create=True):
                with patch('os.path.getsize') as mock_getsize:
                    mock_getsize.side_effect = lambda x: fake_file_sizes.pop()
                    encryptor = self.test_init()

                    with self.assertRaises(IceItException):
                        encryptor.export_keys(public_key_dest=fake_public_key_path, private_key_dest=fake_private_key_path)

    def test_encrypt_no_key_id(self):
        """
        Test encryption raises an exception if there's no key id
        """
        encryptor = self.test_init()
        encryptor.key_id = None

        with self.assertRaises(IceItException):
            encryptor.encrypt('blah', 'blah-again')

    def test_encrypt_non_existent_file(self):
        """
        Test trying to encrypt a non-existent file raises an exception
        """
        encryptor = self.test_init()

        with patch('os.path.exists', return_value=False):
            with self.assertRaises(IceItException):
                encryptor.encrypt('blah', 'blah-again')

    def test_encrypt_success(self):
        """
        Test encryption makes the correct call to gpg
        """
        fake_input_file = 'fake-input-file'
        fake_output_dir = 'fake-output-dir'
        fake_output_extension = '.fake-extension'

        with patch('iceit.crypto.gnupg.GPG') as mock_gpg:
            mock_gpg.return_value = mock_gpg
            with patch('iceit.crypto.open', mock_open(read_data='fake input file data'), create=True) as mock_open_obj:
                with patch('os.path.exists', return_value=True):
                    encryptor = self.test_init()

                    with patch('os.path.getsize', return_value=10):
                        output_file_name = encryptor.encrypt(input_file=fake_input_file, output_dir=fake_output_dir,
                                                             output_extension=fake_output_extension)

                        self.assertEqual(1, mock_gpg.encrypt_file.call_count)

                        # make sure the output file name is composed correctly
                        (call_name, call_args, call_kwargs) = mock_gpg.encrypt_file.mock_calls[0]
                        file_name = call_kwargs['output']
                        self.assertTrue(file_name.startswith(fake_output_dir))
                        self.assertTrue(fake_input_file in file_name)
                        self.assertTrue(file_name.endswith(fake_output_extension))

                        self.assertEqual(file_name, output_file_name)

    def test_encrypt_no_output_exists(self):
        """
        Test that an exception is raised if no output file exists
        """
        fake_input_file = 'fake-input-file'
        fake_output_dir = 'fake-output-dir'
        fake_output_extension = '.fake-extension'

        mock_existence = [False, True]

        with patch('iceit.crypto.gnupg.GPG') as mock_gpg:
            mock_gpg.return_value = mock_gpg
            with patch('iceit.crypto.open', mock_open(read_data='fake input file data'), create=True) as mock_open_obj:
                with patch('os.path.exists', side_effect=lambda x: mock_existence.pop()):
                    encryptor = self.test_init()

                    with self.assertRaises(IceItException):
                        encryptor.encrypt(input_file=fake_input_file, output_dir=fake_output_dir,
                                          output_extension=fake_output_extension)

                    self.assertEqual(1, mock_gpg.encrypt_file.call_count)

    def test_encrypt_no_output_written(self):
        """
        Test that an exception is raised if no output is written
        """
        fake_input_file = 'fake-input-file'
        fake_output_dir = 'fake-output-dir'
        fake_output_extension = '.fake-extension'

        with patch('iceit.crypto.gnupg.GPG') as mock_gpg:
            mock_gpg.return_value = mock_gpg
            with patch('iceit.crypto.open', mock_open(read_data='fake input file data'), create=True) as mock_open_obj:
                with patch('os.path.exists', return_value=True):
                    with patch('os.path.getsize', return_value=0):
                        encryptor = self.test_init()

                        with self.assertRaises(IceItException):
                            encryptor.encrypt(input_file=fake_input_file, output_dir=fake_output_dir,
                                              output_extension=fake_output_extension)

                        self.assertEqual(1, mock_gpg.encrypt_file.call_count)


    def test_encrypt_symmetric_non_existent_input(self):
        """
        Test that symmetric encryption raises an exception if there's no input file
        """
        fake_passphrase = 'fake_passphrase'
        fake_input_file = 'fake-input-file'
        fake_output_dir = 'fake-output-dir'
        fake_output_extension = '.fake-extension'

        with patch('os.path.exists', return_value=False):
            encryptor = self.test_init()

            with self.assertRaises(IceItException):
                encryptor.encrypt_symmetric(passphrase=fake_passphrase, input_file=fake_input_file,
                                            output_dir=fake_output_dir, output_extension=fake_output_extension)

    def test_encrypt_symmetric(self):
        """
        Test that symmetric encryption makes the correct calls
        """
        fake_passphrase = 'fake_passphrase'
        fake_input_file = 'fake-input-file'
        fake_output_dir = 'fake-output-dir'
        fake_output_extension = '.fake-extension'

        with patch('os.path.exists', return_value=True):
            with patch('iceit.crypto.gnupg.GPG') as mock_gpg:
                mock_gpg.return_value = mock_gpg
                with patch('iceit.crypto.open', mock_open(read_data="fake input file data"), create=True) as mock_open_obj:
                    encryptor = self.test_init()

                    output_file_name = encryptor.encrypt_symmetric(
                        passphrase=fake_passphrase, input_file=fake_input_file,
                        output_dir=fake_output_dir, output_extension=fake_output_extension)

                    self.assertEqual(1, mock_gpg.encrypt_file.call_count)

                    # make sure the output file name is composed correctly
                    (call_name, call_args, call_kwargs) = mock_gpg.encrypt_file.mock_calls[0]
                    self.assertTrue(call_kwargs['symmetric'])
                    file_name = call_kwargs['output']
                    self.assertTrue(file_name.startswith(fake_output_dir))
                    self.assertTrue(fake_input_file in file_name)
                    self.assertTrue(file_name.endswith(fake_output_extension))

                    self.assertEqual(file_name, output_file_name)