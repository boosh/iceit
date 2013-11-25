import unittest
from mock import patch, Mock, PropertyMock
from StringIO import StringIO

from iceit.backends import S3Backend, S3ResponseError

class TestS3Backend(unittest.TestCase):
    """
    Tests for the S3 backend
    """
    def test_init_valid(self):
        """
        Test that it can be initialised when using valid credentials
        """
        access_key = 'fake_key'
        secret_key = 'fake_secret'
        bucket_name = 'fake_bucket'
        location = 'anywhere'

        with patch('boto.connect_s3') as mock_connect_s3:
            mock_conn = Mock()
            mock_connect_s3.return_value = mock_conn

            backend = S3Backend(access_key=access_key, secret_key=secret_key,
                                bucket_name=bucket_name, s3_location=location)
            mock_connect_s3.assert_called_once_with(access_key, secret_key)
            mock_conn.get_bucket.assert_called_once_with(bucket_name)

        return backend

    def test_init_invalid(self):
        """
        Test how it handles an init failure not due to a bucket not existing
        """
        access_key = 'fake_key'
        secret_key = 'fake_secret'
        bucket_name = 'fake_bucket'
        location = 'anywhere'

        with patch('boto.connect_s3') as mock_connect_s3:
            mock_conn = Mock()
            mock_conn.get_bucket.side_effect = S3ResponseError(999, "Failed")
            mock_connect_s3.return_value = mock_conn

            self.assertRaises(S3ResponseError, S3Backend, access_key, secret_key,
                              bucket_name, location)
            mock_connect_s3.assert_called_once_with(access_key, secret_key)
            mock_conn.get_bucket.assert_called_once_with(bucket_name)

    def test_init_auto_create_bucket(self):
        """
        Test that it automatically creates a bucket that doesn't exist
        """
        access_key = 'fake_key'
        secret_key = 'fake_secret'
        bucket_name = 'fake_bucket'
        location = 'anywhere'

        with patch('boto.connect_s3') as mock_connect_s3:
            mock_error = S3ResponseError(999, "Failed")
            mock_error.error_code = "NoSuchBucket"
            mock_conn = Mock()
            mock_conn.get_bucket.side_effect = mock_error

            mock_connect_s3.return_value = mock_conn

            S3Backend(access_key=access_key, secret_key=secret_key,
                      bucket_name=bucket_name, s3_location=location)

            mock_connect_s3.assert_called_once_with(access_key, secret_key)
            mock_conn.get_bucket.assert_called_once_with(bucket_name)

            mock_conn.create_bucket.assert_called_once_with(bucket_name, location=location)

    def test_download(self):
        """
        Test downloading works
        """
        fake_file_name = 'fake_file'
        fake_contents = "This is the file contents"

        with patch('iceit.backends.Key', spec=True) as mock_key:
            with patch('iceit.backends.TemporaryFile', new_callable=StringIO) as mock_file:
                backend = self.test_init_valid()
                mock_file.write(fake_contents)

                out_file = backend.download(fake_file_name)

                assert out_file == mock_file

                self.assertEqual(out_file.tell(), 0)
                self.assertEqual(out_file.read(), fake_contents)
                mock_key.assert_called_once_with(backend.bucket, fake_file_name)
                mock_key.get_contents_to_file.assert_called_once_with(mock_file)