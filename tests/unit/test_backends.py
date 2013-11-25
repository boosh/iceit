import unittest
from mock import patch, Mock, PropertyMock
from StringIO import StringIO
from collections import namedtuple

from iceit.backends import S3Backend, S3ResponseError, GlacierBackend

class TestS3Backend(unittest.TestCase):
    """
    Tests for the S3 backend
    """
    def test_init_valid(self):
        """
        Test that S3 can be initialised when using valid credentials
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
        fake_contents = "This is the file contents"
        fake_key_name = 'fake_key_name'

        with patch('iceit.backends.TemporaryFile', spec=True) as mock_file:
            string_file = StringIO()
            string_file.write(fake_contents)
            mock_file.return_value = string_file

            with patch('iceit.backends.Key', spec=True) as mock_key:
                mock_key.return_value = mock_key
                backend = self.test_init_valid()
                result = backend.download(fake_key_name)

                assert result is string_file
                self.assertEqual(result.tell(), 0)
                self.assertEqual(result.read(), fake_contents)
                mock_key.assert_called_once_with(backend.bucket, fake_key_name)
                mock_key.get_contents_to_file.assert_called_once_with(string_file)

    def test_upload(self):
        """
        Test that uploading works
        """
        fake_key_name = 'fake_key_name'
        fake_file_name = 'fake_file_name'

        with patch('iceit.backends.Key', spec=True) as mock_key:
            mock_key.return_value = mock_key
            backend = self.test_init_valid()

            backend.upload(fake_key_name, fake_file_name)
            mock_key.assert_called_once_with(backend.bucket, fake_key_name)
            self.assertTrue(mock_key.encrypted)
            self.assertTrue(mock_key.set_contents_from_filename.called)
            mock_key.set_acl.assert_called_once_with("private")

    def test_ls(self):
        """
        Test ls returns data
        """
        fake_key = namedtuple('Key', ['name'])
        num_items = 10
        items = []
        for i in range(num_items):
            items.append('item_%d' % i)

        backend = self.test_init_valid()

        backend.bucket.get_all_keys.return_value = [fake_key(name) for name in items]

        results = backend.ls()
        self.assertEqual(len(results), num_items)
        self.assertEqual(results, items)

    def test_delete(self):
        """
        Test deletion works
        """
        fake_key_name = 'fake_key_name'

        with patch('iceit.backends.Key', spec=True) as mock_key:
            mock_key.return_value = mock_key
            backend = self.test_init_valid()
            backend.delete(fake_key_name)

            mock_key.assert_called_once_with(backend.bucket, fake_key_name)
            backend.bucket.delete_key.assert_called_once_with(mock_key)


class TestGlacierBackend(unittest.TestCase):
    """
    Tests for the Glacier backend
    """
    def test_init_valid(self):
        """
        Test that Glacier can be initialised when using valid credentials
        """
        access_key = 'fake_key'
        secret_key = 'fake_secret'
        vault_name = 'fake_vault'
        region_name = 'anywhere'

        with patch('boto.connect_glacier') as mock_connect_glacier:
            mock_conn = Mock()
            mock_connect_glacier.return_value = mock_conn

            backend = GlacierBackend(access_key=access_key, secret_key=secret_key,
                vault_name=vault_name, region_name=region_name)
            mock_connect_glacier.assert_called_once_with(region_name=region_name, aws_secret_access_key=secret_key,
                                                         aws_access_key_id=access_key)
            mock_conn.create_vault.assert_called_once_with(vault_name)

        return backend