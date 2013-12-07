import unittest
import os.path
import copy
from datetime import datetime
from mock import patch, Mock, mock_open

from iceit.iceit import IceIt

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
                ('processing', 'exclude_patterns', '.*1$,.*2$'),     # exclude files ending with a 1 or a 2
                ('processing', 'disable_compression_patterns',
                 ".*\.nocompress$,.*\.uncompressed$")   # don't compress files with these suffixes
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

                    self.assertIs(iceit.glacier_backend, mock_glacier_backend)
                    self.assertIs(iceit.s3_backend, mock_s3_backend)

    @patch('iceit.iceit.S3Backend')
    @patch('iceit.iceit.GlacierBackend')
    @patch('iceit.iceit.Catalogue')
    def test_trim_ineligible_files_exclude_patterns(self, mock_catalogue, *args):
        """
        Test that ineligible file exclusion patterns are applied
        """
        num_fake_files = 10
        fake_files = set(["/my/fake/file%d" % i for i in range(num_fake_files)])

        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()

        mock_catalogue.return_value = mock_catalogue

        with patch('iceit.iceit.Config', new=mock_config):
            iceit = IceIt(config_profile=fake_profile)
            iceit.catalogue = mock_catalogue
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
        Test that ineligible files already backed up and that haven't changed are removed correctly
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
                    iceit.catalogue = mock_catalogue
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

    @patch('iceit.iceit.GlacierBackend')
    @patch('iceit.iceit.Catalogue')
    @patch('iceit.iceit.Encryptor')
    @patch('iceit.iceit.S3Backend')
    @patch('os.unlink')
    @patch('iceit.iceit.tarfile')
    def test_backup_catalogue_and_config(self, mock_tarfile, mock_unlink, mock_s3_backend, mock_encryptor, *args):
        """
        Test the catalogue and config are backed up correctly
        """
        fake_temporary_file_handle = 'fake_temporary_file_handle'
        fake_temporary_file_path = '/my/dir/fake_temporary_file_path'

        fake_catalogue_path = '/my/fake/catalogue_path'
        fake_config_file_path = '/a/fake/config_file_path'
        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()
        mock_config.get_catalogue_path.return_value = fake_catalogue_path
        mock_config.get_config_file_path.return_value = fake_config_file_path

        mock_tarfile.return_value = mock_tarfile
        mock_tarfile.open.return_value = mock_tarfile

        fake_encrypted_file_path = 'fake_encrypted_file_path'

        mock_encryptor.return_value = mock_encryptor
        mock_encryptor.encrypt.return_value = fake_encrypted_file_path

        mock_s3_backend.return_value = mock_s3_backend
        mock_s3_backend.upload.return_value = mock_s3_backend

        with patch('iceit.iceit.Config', new=mock_config):
            with patch('iceit.iceit.mkstemp') as mock_mkstemp:
                mock_mkstemp.return_value = (fake_temporary_file_handle, fake_temporary_file_path)

                iceit = IceIt(config_profile=fake_profile)

                iceit._IceIt__backup_catalogue_and_config()

                self.assertEqual(1, mock_mkstemp.call_count)
                self.assertEqual(1, mock_tarfile.open.call_count)
                mock_tarfile.add.assert_any_call(name=fake_catalogue_path, arcname=os.path.basename(fake_catalogue_path))
                mock_tarfile.add.assert_any_call(name=fake_config_file_path, arcname=os.path.basename(fake_config_file_path))

                mock_encryptor.encrypt.assert_called_once_with(output_dir=os.path.dirname(fake_temporary_file_path), input_file=fake_temporary_file_path)

                self.assertEqual(1, mock_s3_backend.upload.call_count)
                mock_s3_upload_args = mock_s3_backend.upload.call_args
                self.assertEqual(fake_encrypted_file_path, mock_s3_upload_args[0][1])

                self.assertEqual(2, mock_unlink.call_count)

    @patch('iceit.iceit.Catalogue')
    @patch('os.path.isdir')
    def test_backup(self, mock_isdir, mock_catalogue):
        """
        Test the right calls are made to back up files
        """
        mock_isdir.return_value = False

        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()

        mock_catalogue.return_value = mock_catalogue

        fake_paths = ['/my/fake/path/a', '/my/fake/path/b', '/my/fake/path/c']

        with patch('iceit.iceit.Config', new=mock_config):
            iceit = IceIt(config_profile=fake_profile)
            iceit.catalogue = mock_catalogue

            mock_initialise_backends = Mock()
            mock_trim_ineligible_files = Mock()
            mock_trim_ineligible_files.return_value = fake_paths
            mock_process_files = Mock()
            mock_backup_catalogue_and_config = Mock()

            # mock the complex methods and just assert they're called
            iceit._IceIt__initialise_backends = mock_initialise_backends
            iceit._IceIt__trim_ineligible_files = mock_trim_ineligible_files
            iceit._IceIt__process_files = mock_process_files
            iceit._IceIt__backup_catalogue_and_config = mock_backup_catalogue_and_config

            iceit.backup(paths=fake_paths, recursive=False)

            mock_initialise_backends.assert_called_once_with()
            mock_trim_ineligible_files.assert_called_once_with(set(fake_paths))
            mock_process_files.assert_called_once_with(fake_paths)
            mock_backup_catalogue_and_config.assert_called_once_with()

    @patch('os.rmdir')
    @patch('os.path.getmtime')
    @patch('os.unlink')
    @patch('iceit.iceit.S3Backend')
    @patch('iceit.iceit.GlacierBackend')
    @patch('os.symlink')
    @patch('os.rename')
    @patch('iceit.iceit.StringUtils')
    @patch('iceit.iceit.Encryptor')
    @patch('iceit.iceit.mkdtemp')
    @patch('iceit.iceit.FileUtils')
    @patch('iceit.iceit.Catalogue')
    def test_process_files(self, mock_catalogue, mock_file_utils, mock_mkdtemp, mock_encryptor,
                           mock_string_utils, mock_os_rename, mock_os_symlink,
                           mock_glacier_backend, mock_s3_backend, mock_os_unlink, mock_os_getmtime,
                           mock_os_rmdir):
        """
        Test that files are processed for backing up correctly
        """
        fake_mtime = 1234567890.0
        mock_os_getmtime.return_value = fake_mtime

        mock_glacier_backend.upload.side_effect = lambda file_name: "aws-archive-id-for-%s" % os.path.basename(file_name)

        mock_string_utils.return_value = mock_string_utils
        mock_string_utils.get_random_string.return_value = 'fake_random_string'

        mock_encryptor.return_value = mock_encryptor
        mock_encryptor.encrypt.side_effect = lambda file_name, dir: os.path.join(dir, "%s-encrypted" % file_name)

        fake_temp_dir = '/a/fake/temp/dir'
        mock_mkdtemp.side_effect = lambda suffix: fake_temp_dir + str(suffix)

        mock_file_utils.return_value = mock_file_utils
        fake_file_hash = 'fake_file_hash'
        mock_file_utils.get_file_hash.side_effect = lambda path: "fake_file_hash-for-%s" % os.path.basename(path)

        mock_file_utils.compress_file.side_effect = lambda file_name, dir: os.path.join(dir, "%s-compressed" % file_name)

        fake_eligible_files = set([
            '/my/fake/path/filea',
            '/my/fake/path/fileb',
            '/my/fake/path/filec',
            '/my/fake/path/filed.nocompress',       # matches our canned no-compression regex
            '/my/fake/path/filee.uncompressed',     # as above
        ])

        mock_catalogue.return_value = mock_catalogue

        fake_profile = "fake_profile"
        mock_config = self.__get_fake_config()

        mock_config.getboolean.return_value = True

        with patch('iceit.iceit.Config', new=mock_config):
            iceit = IceIt(config_profile=fake_profile)

            mock_encryption_enabled = Mock()
            mock_encryption_enabled.return_value = True
            iceit.encryption_enabled =  mock_encryption_enabled

            iceit.encryptor = mock_encryptor
            iceit.catalogue = mock_catalogue
            iceit.glacier_backend = mock_glacier_backend
            iceit.config = mock_config

            iceit._IceIt__process_files(fake_eligible_files)

            self.assertEqual(len(fake_eligible_files), mock_catalogue.get.call_count)
            self.assertEqual(len(fake_eligible_files)*2, mock_file_utils.get_file_hash.call_count)
            self.assertEqual(len(fake_eligible_files)-2, mock_file_utils.compress_file.call_count)
            self.assertEqual(len(fake_eligible_files), mock_encryptor.encrypt.call_count)
            self.assertEqual(len(fake_eligible_files), mock_os_symlink.call_count)
            self.assertEqual(len(fake_eligible_files), mock_glacier_backend.upload.call_count)

            for (args, kwargs) in mock_glacier_backend.upload.call_args_list:
                self.assertEqual('/a/fake/temp/dir-iceit/fake_random_string', args[0])

            unseen_fake_eligible_files = copy.copy(fake_eligible_files)

            self.assertEqual(len(fake_eligible_files), mock_catalogue.add_item.call_count)
            for (args, kwargs) in mock_catalogue.add_item.call_args_list:
                source_path = kwargs['item']['source_path']
                expected_source_hash = 'fake_file_hash-for-%s' % os.path.basename(source_path)
                self.assertEqual(kwargs['item']['source_hash'], expected_source_hash)
                unseen_fake_eligible_files.discard(kwargs['item']['source_path'])

            self.assertEqual(len(unseen_fake_eligible_files), 0)