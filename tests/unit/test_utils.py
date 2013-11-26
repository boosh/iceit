import unittest
import shutil
import os.path
import copy
from tempfile import mkstemp, mkdtemp
from mock import patch, Mock, mock_open

from iceit.utils import SetUtils, StringUtils, FileFinder, FileUtils

class TestSetUtils(unittest.TestCase):
    """
    Tests for SetUtils
    """
    def test_match_patterns(self):
        """
        Test the match_patterns method
        """
        items = ['cat', 'rat', 'bat', 'dog']
        input = set(items)

        results = SetUtils.match_patterns(input, '.*at$')

        self.assertEqual(set(items[:3]), results)
        self.assertEqual(3, len(results))


class TestStringUtils(unittest.TestCase):
    """
    Tests for StringUtils
    """
    def test_get_random_string(self):
        """
        Test get_random_string
        """
        random_string = StringUtils.get_random_string(length=32)
        self.assertEqual(32, len(random_string))
        self.assertRegexpMatches(random_string, '[a-zA-Z0-9]{32}')


class TestFileFinder(unittest.TestCase):
    """
    Tests for FileFinder
    """
    DUD_DIR_PREFIX = '/tmp/iceit-test-safe-to-delete'
    FILES_PER_DIR = [3,6,5]                 # the number of temporary files to create per directory

    @classmethod
    def setUpClass(cls):
        """
        Create dud file structure before beginning
        """
        if os.path.exists(cls.DUD_DIR_PREFIX):
            print "Deleting old test directory %s" % cls.DUD_DIR_PREFIX
            cls.tearDownClass()
        cls.__create_dud_files(dir=cls.DUD_DIR_PREFIX, num_files=copy.copy(cls.FILES_PER_DIR))

    @classmethod
    def __create_dud_files(cls, dir, num_files):
        """
        Create a simple set of temporary files and directories we can test against (avoids having to mock
        os.walk() too much
        """
        if not os.path.exists(dir):
            os.mkdir(dir)

        for i in range(num_files.pop()):
            (handle, path) = mkstemp(dir=dir)
            print "Created file %s" % path

        if len(num_files) > 0:
            dir = mkdtemp(dir=dir + '/')
            print "Created dir %s" % dir
            
            print "Creating another set with dir %s" % dir
            cls.__create_dud_files(dir=dir, num_files=num_files)

    def test_get_files_non_recursive(self):
        """
        Test that we can find files non-recusively
        """
        file_finder = FileFinder(path=self.DUD_DIR_PREFIX, recursive=False)
        files = file_finder.get_files()

        self.assertEqual(len(files), self.FILES_PER_DIR[len(self.FILES_PER_DIR) - 1])

    def test_get_files_recursive(self):
        """
        Test that we can find files recusively
        """
        file_finder = FileFinder(path=self.DUD_DIR_PREFIX, recursive=True)
        files = file_finder.get_files()

        self.assertEqual(len(files), sum(self.FILES_PER_DIR))

    def test_get_file_hash(self):
        """
        Test file hashes are calculated correctly
        """
        def permit_single_call():
            data = ['fake input file data', None]
            for d in data:
                yield d

        with patch('iceit.utils.open', mock_open(read_data='fake input file data'), create=True) as mock_open_obj:
            mock_handle = mock_open_obj.return_value
            mock_handle.read.side_effect = permit_single_call()
            calculated_hash = FileUtils.get_file_hash('fake_path')
            self.assertEqual('1de7e43607d31ade4a1f380f660d7b70410e35a12b7347edad92ddf21bbd2e7d', calculated_hash)

    @classmethod
    def tearDownClass(cls):
        """
        Delete the temporary dir tree
        """
        shutil.rmtree(cls.DUD_DIR_PREFIX)
