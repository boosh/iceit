import unittest
import os
import copy
from datetime import datetime
from tempfile import mkstemp
from mock import patch, Mock, mock_open

from iceit.catalogue import Catalogue

class TestCatalogue(unittest.TestCase):
    """
    Test the Catalogue class. Not mocking the backend because it needs to be
    thoroughly tested.
    """
    def setUp(self):
        """
        Create a new catalogue for each test
        """
        (handle, self.temp_db_path) = mkstemp(suffix='.sqlite')
        self.catalogue = Catalogue(dbpath=self.temp_db_path)

    def __build_items(self, include_id=False):
        """
        Build a list of items to test.

        @param include_id: If True, an ID field will be included
        @return list: A list of dicts representing items
        """
        self.num_items = 5
        self.base_path = '/my/path/file'
        items = []

        for i in range(1, self.num_items+1):
            item = {
                'source_path': "%s%s" % (self.base_path, i),
                'aws_archive_id': i,
                'file_mtime': datetime(year=2013, month=4, day=i),
                'source_hash': str(i) * 5,
                'processed_hash': str(i) * 10,
                'last_backed_up': datetime(year=2013, month=5, day=i)
            }

            if include_id == True:
                item['id'] = i

            items.append(copy.copy(item))

        return items

    def test_add_item_insert(self):
        """
        Test inserting items into the catalogue
        """
        for item in self.__build_items():
            self.assertTrue(self.catalogue.add_item(item=item))

    def test_add_item_update(self):
        """
        Test inserting items into the catalogue
        """
        self.test_add_item_insert()

        for item in self.__build_items(include_id=True):
            id = item['id']
            item['source_hash'] = str(item['id']) * 8
            item['last_backed_up'] = datetime(year=2013, month=8, day=id)
            del(item['id'])
            self.assertTrue(self.catalogue.add_item(item=item, id=id))

    def test_insert_duplicate_file_names(self):
        """
        Test setting an item with the same file name is allowed
        """
        fake_hash = 'asdf'
        items = self.__build_items()
        item = items[0]

        self.assertTrue(self.catalogue.add_item(item=item))
        item['source_hash'] = fake_hash

        self.assertTrue(self.catalogue.add_item(item=item))
        return fake_hash

    def test_get_duplicate_file_names(self):
        """
        Trest retrieving an item which has duplicate entries in the catalogue
        returns all entries
        """
        items = self.__build_items()
        item = items[0]

        fake_hash = self.test_insert_duplicate_file_names()

        retrieved_items = self.catalogue.get(item['source_path'])

        self.assertEqual(2, len(retrieved_items))

        found_normal_hash = False
        found_fake_hash = False
        for retrieved_item in retrieved_items:
            if retrieved_item['source_hash'] == item['source_hash']:
                found_normal_hash = True
            elif retrieved_item['source_hash'] == fake_hash:
                found_fake_hash = True

        self.assertTrue(found_fake_hash)
        self.assertTrue(found_normal_hash)

    def test_get(self):
        """
        Test retrieving items
        """
        self.test_add_item_insert()

        for item in self.__build_items(include_id=True):
            retrieved_item = self.catalogue.get(item['source_path'])
            retrieved_item = dict(retrieved_item[0])

            print "Asserting item id %s" % str(retrieved_item['id'])

            del(retrieved_item['id'])

            for k, v in retrieved_item.iteritems():
                self.assertEqual(str(item[k]), str(v))

    def test_get_with_updates(self):
        """
        Test retrieving items that have been updated
        """
        self.test_add_item_update()

        for item in self.__build_items(include_id=True):
            retrieved_item = self.catalogue.get(item['source_path'])
            retrieved_item = dict(retrieved_item[0])

            id = str(item['id'])

            item['source_hash'] = id * 8
            item['last_backed_up'] = datetime(year=2013, month=8, day=int(id))

            print "Asserting item id %s" % id

            del(retrieved_item['id'])

            for k, v in retrieved_item.iteritems():
                self.assertEqual(str(item[k]), str(v))

    def tearDown(self):
        """
        Delete the temporary catalogue
        """
        if os.path.exists(self.temp_db_path):
            print "Deleting temporary database"
            os.unlink(self.temp_db_path)