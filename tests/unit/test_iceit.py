import unittest
from mock import patch, Mock, mock_open

from iceit.iceit import IceIt

class TestIceit(unittest.TestCase):
    """
    Test the IceIt class
    """
    def __get_fake_config(self):
        """
        Return a fake config object
        """
        def fake_get(section, title):
            """
            Just return a string derived from the given section and title
            """
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