import hashlib
import os
import re
import string
import random
import logging

log = logging.getLogger(__name__)

if not log.handlers:
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')


class SetUtils(object):
    "Provides utility methods on sets"

    @staticmethod
    def match_patterns(search_set, pattern):
        "Return a new set containing elements from search_set that match the given regex pattern"
        log.info("Excluding files matching pattern '%s'" % pattern)
        matching_set = set()
        regex = re.compile(pattern, re.IGNORECASE)
        for item in search_set:
            if regex.match(item) is not None:
                matching_set.add(item)

        return matching_set


class StringUtils(object):
    "Utilities on strings"

    @staticmethod
    def get_random_string(length=32):
        return ''.join(random.choice(
            string.ascii_letters + string.digits) for x in range(length))


class FileFinder(object):
    "Finds files using different methods"

    def __init__(self, path, recursive=False):
        """
        @param string start - Path to scan
        @param bool recursive - Whether to scan recursively or just return
            files in the input directory.
        """
        log.debug("Initialising file finder with path '%s', recursive=%s" % (path, recursive))
        self.path = unicode(path)
        self.recursive = recursive
        self.files = None

    def get_files(self):
        "Return a set of files for the given operating mode."
        if self.recursive:
            self.files = self.__get_files_recursive()
        else:
            self.files = self.__get_files_non_recursive()

        log.debug("Returning %d files: %s" % (len(self.files), self.files))

        return self.files

    def __get_files_non_recursive(self):
        "Only return files from the input directory."
        for (path, dirs, files) in os.walk(self.path):
            log.debug("(Non-recursive file finder):Found %d files in %s: %s" % (len(files), self.path, files))
            return set([os.path.join(path, f) for f in files])

    def __get_files_recursive(self):
        "Return all matching files"
        output = set()

        for (path, dirs, files) in os.walk(self.path):
            log.debug("(Recursive file finder):Found %d files in %s: %s" % (len(files), self.path, files))
            full_files = [os.path.join(path, f) for f in files]
            if full_files:
                output.update(full_files)

        return output


class FileUtils(object):
    """
    Misc utils on files
    """
    @staticmethod
    def get_file_hash(file_path):
        """
        Generate a hash of the named file
        """
        hash = hashlib.sha256()
        with open(file_path) as file:
            while True:
                data = file.read(1024*1024)
                if not data:
                    break

                hash.update(data)

        return hash.hexdigest()
