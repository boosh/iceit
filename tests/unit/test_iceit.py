import unittest
import os.path
from datetime import datetime
from mock import patch, Mock, mock_open

from iceit.iceit import IceIt
from iceit.crypto import Encryptor

class TestIceIt(unittest.TestCase):
    """
    Test the IceIt class
    """
    def __get_fake_config(self):
        """
        Return a fake config object
        """
        def fake_get(section, title):
            """
            Just return a string derived from the given section and title unless
            explicitly overridden
            """
            canned_values = [
                ('processing', 'exclude_patterns', '.*1$,.*2$')     # exclude files ending with a 1 or a 2
            ]

            for canned_value in canned_values:
                if canned_value[0] == section and canned_value[1] == title:
                    print "Returning canned value for section '%s', title '%s' of '%s'" % (section, title, canned_value[2])
                    return canned_value[2]

            fake_value = "fake__%s__%s" % (section, title)
            print "Returning fake value for section '%s', title '%s' of '%s'" % (section, title, fake_value)
            return fake_value

        mock_config = Mock()
        mock_config.return_value = mock_config
        mock_config.get.side_effect = fake_get

        return mock_config

    def test_init(self):
        """
        Test it can be initialised
        """
        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()

        with patch('iceit.iceit.Config', new=mock_config):
            iceit = IceIt(config_profile=fake_profile)
            self.assertEqual(fake_profile, iceit.config_profile)
            self.assertIsNone(iceit.catalogue)

    def test_initialise_backends(self):
        """
        Test the backends are initialised correctly
        """
        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()

        with patch('iceit.iceit.Config', new=mock_config):
            with patch('iceit.iceit.GlacierBackend') as mock_glacier_backend:
                mock_glacier_backend.return_value = mock_glacier_backend
                with patch('iceit.iceit.S3Backend') as mock_s3_backend:
                    mock_s3_backend.return_value = mock_s3_backend

                    iceit = IceIt(config_profile=fake_profile)
                    iceit._IceIt__initialise_backends()

                    mock_glacier_backend.assert_called_once_with('fake__aws__access_key', 'fake__aws__secret_key',
                        'fake__aws__glacier_vault', 'fake__aws__glacier_region')
                    mock_s3_backend.assert_called_once_with('fake__aws__access_key', 'fake__aws__secret_key',
                        'fake__aws__s3_bucket', 'fake__aws__s3_location')

                    self.assertIs(iceit.long_term_storage_backend, mock_glacier_backend)
                    self.assertIs(iceit.ha_storage_backend, mock_s3_backend)

    @patch('iceit.iceit.S3Backend')
    @patch('iceit.iceit.GlacierBackend')
    @patch('iceit.iceit.Catalogue')
    def test_trim_ineligible_files_exclude_patterns(self, *args):
        """
        Test that ineligible file exclusion patterns are applied
        """
        num_fake_files = 10
        fake_files = set(["/my/fake/file%d" % i for i in range(num_fake_files)])

        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()

        with patch('iceit.iceit.Config', new=mock_config):
            iceit = IceIt(config_profile=fake_profile)
            results = iceit._IceIt__trim_ineligible_files(fake_files)

            self.assertEqual(num_fake_files-2, len(results))

    @patch('iceit.iceit.S3Backend')
    @patch('iceit.iceit.GlacierBackend')
    @patch('iceit.iceit.Catalogue')
    def test_trim_ineligible_files_empty_set(self, *args):
        """
        Test that no potential files returns correctly
        """
        fake_files = set()

        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()

        with patch('iceit.iceit.Config', new=mock_config):
            iceit = IceIt(config_profile=fake_profile)
            results = iceit._IceIt__trim_ineligible_files(fake_files)

            self.assertEqual(0, len(results))

    @patch('iceit.iceit.S3Backend')
    @patch('iceit.iceit.GlacierBackend')
    @patch('iceit.iceit.Catalogue')
    def test_trim_ineligible_files_trims_correctly(self, mock_catalogue, *args):
        """
        Test that ineligible files already backed up and that haven't changed are removed
        correctly
        """
        fake_mtime = 1234567890.0
        fake_source_hash = 'abcdefgh'

        # start at 3 because the first 2 file will be removed by our canned exclusion rules
        fake_files = set(["/my/fake/file%d" % i for i in range(3, 11)])

        def fake_catalogue_get(path):
            """
            Return canned responses for some paths so they'll be removed
            """
            print "fake_catalogue_get called with path '%s'" % path
            mock_object = Mock()
            if path.endswith('3'):
                print "Applying canned file_mtime to mock %s" % mock_object
                mock_object.file_mtime = datetime.fromtimestamp(fake_mtime)
            elif path.endswith('4'):
                print "Applying canned file_hash to mock %s" % mock_object
                mock_object.source_hash = fake_source_hash

            return [mock_object]

        mock_catalogue.return_value = mock_catalogue
        mock_catalogue.get.side_effect = fake_catalogue_get

        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()

        with patch('iceit.iceit.Config', new=mock_config):
            with patch('os.path.getmtime') as mock_getmtime:
                mock_getmtime.return_value = fake_mtime
                with patch('iceit.iceit.FileUtils') as mock_file_utils:
                    mock_file_utils.get_file_hash.return_value = fake_source_hash

                    iceit = IceIt(config_profile=fake_profile)
                    results = iceit._IceIt__trim_ineligible_files(fake_files)

                    # 2 files should have been skipped
                    self.assertEqual(len(fake_files)-2, len(results))
                    # 1 will have been skipped based on mtime so shouldn't have been hashed
                    self.assertEqual(len(fake_files)-1, mock_file_utils.get_file_hash.call_count)

    @patch('iceit.iceit.GlacierBackend')
    @patch('iceit.iceit.Catalogue')
    @patch('iceit.iceit.Encryptor')
    @patch('iceit.iceit.S3Backend')
    @patch('os.unlink')
    @patch('iceit.iceit.tarfile')
    def test_backup_encryption_keys(self, mock_tarfile, mock_unlink, mock_s3_backend, mock_encryptor, *args):
        """
        Test encryption keys are backed up correctly
        """
        fake_temporary_file_handle = 'fake_temporary_file_handle'
        fake_temporary_file_path = '/my/dir/fake_temporary_file_path'

        fake_public_key_path = 'fake_public_key_path'
        fake_private_key_path = 'fake_private_key_path'
        fake_passphrase = 'fake_passphrase'
        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()
        mock_config.get_public_key_path.return_value = fake_public_key_path
        mock_config.get_private_key_path.return_value = fake_private_key_path

        mock_tarfile.return_value = mock_tarfile
        mock_tarfile.open.return_value = mock_tarfile

        fake_encrypted_file_path = 'fake_encrypted_file_path'

        mock_encryptor.return_value = mock_encryptor
        mock_encryptor.encrypt_symmetric.return_value = fake_encrypted_file_path

        mock_s3_backend.return_value = mock_s3_backend
        mock_s3_backend.upload.return_value = mock_s3_backend

        with patch('iceit.iceit.Config', new=mock_config):
            with patch('iceit.iceit.mkstemp') as mock_mkstemp:
                mock_mkstemp.return_value = (fake_temporary_file_handle, fake_temporary_file_path)

                iceit = IceIt(config_profile=fake_profile)

                iceit.backup_encryption_keys(symmetric_passphrase=fake_passphrase)

                self.assertEqual(1, mock_mkstemp.call_count)
                self.assertEqual(1, mock_tarfile.open.call_count)
                mock_tarfile.add.assert_any_call(fake_public_key_path)
                mock_tarfile.add.assert_any_call(fake_private_key_path)

                mock_encryptor.encrypt_symmetric.assert_called_once_with(output_dir=os.path.dirname(fake_temporary_file_path),
                    passphrase=fake_passphrase, input_file=fake_temporary_file_path)

                self.assertEqual(1, mock_s3_backend.upload.call_count)
                mock_s3_upload_args = mock_s3_backend.upload.call_args
                self.assertEqual(fake_encrypted_file_path, mock_s3_upload_args[0][1])

                self.assertEqual(2, mock_unlink.call_count)