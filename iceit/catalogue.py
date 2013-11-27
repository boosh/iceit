import logging
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, DateTime, select

log = logging.getLogger(__name__)

if not log.handlers:
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

class Catalogue(object):
    """
    Encapsulates the catalogue - the database of files stored, their modification times and hashes.
    """
    def __init__(self, dbpath):
        self.tables = {}
        self.engine = create_engine('sqlite:///%s' % dbpath)
        self.__create_tables()

        self.conn = self.engine.connect()

    def __create_tables(self):
        "Create necessary tables"
        log.info("Creating DB tables...")
        metadata = MetaData()
        self.tables['files'] = Table('files', metadata,
            Column('id', Integer, primary_key=True),
            Column('source_path', String),
            Column('aws_archive_id', String),
            Column('file_mtime', DateTime),
            Column('source_hash', String),
            Column('processed_hash', String),
            Column('last_backed_up', DateTime)
        )

        metadata.create_all(self.engine)
        log.info("DB tables created...")

    def close(self):
        """
        Close the connection
        """
        return self.conn.close()

    def get(self, file_path):
        "Get a file entry or return an empty list if not found"
        file_table = self.tables['files']

        log.debug("Searching for file %s in catalogue..." % file_path)
        query = select([file_table], file_table.c.source_path==file_path)
        result = self.conn.execute(query)

        rows = result.fetchall()

        log.debug("%d record(s) found." % len(rows))

        return rows

    def add_item(self, item, id=None):
        """
        Add an item to the catalogue, or update the one with the given ID

        @param dict item - A dictionary where keys correspond to column names in the 'files' table.
        """
        file_table = self.tables['files']
        if id:
            # update
            log.debug("Updating item with id='%s' with value=%s" % (id, item))
            query = file_table.update().where(file_table.c.id==id).values(item)
        else:
            # insert
            log.debug("Inserting item '%s' into catalogue" % item)
            query = file_table.insert().values(item)

        result = self.conn.execute(query)
        log.debug("Result was: %s" % result)

        return result

    #@todo: add a method that returns a count of objects in the database

    #@todo: add a method that returns a list of objects in the database, possibly supporting filtering