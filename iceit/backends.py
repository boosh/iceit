import boto.glacier
import boto.s3
from time import sleep

from boto.s3.key import Key
from boto.exception import S3ResponseError
from boto.glacier.exceptions import UploadArchiveError
from tempfile import TemporaryFile
from .log import get_logger

log = get_logger(__name__)


class S3Backend:
    """
    Backend to handle S3 upload/download
    """
    def __init__(self, access_key, secret_key, bucket_name, s3_location):
        log.info("Connecting to S3...")
        conn = boto.connect_s3(access_key, secret_key)

        log.info("Done. Retrieving or creating bucket %s" % bucket_name)
        try:
            self.bucket = conn.get_bucket(bucket_name)
        except S3ResponseError as e:
            if e.code == "NoSuchBucket":
                self.bucket = conn.create_bucket(bucket_name, location=s3_location)
            else:
                raise e
        log.info("Done")

    def download(self, key_name):
        """
        Download a file

        @param string key_name - Key of the file to download
        """
        key = Key(self.bucket, key_name)

        encrypted_out = TemporaryFile()
        log.debug("Saving contents of key %s to file %s" % (key_name, encrypted_out))
        key.get_contents_to_file(encrypted_out)
        encrypted_out.seek(0)

        return encrypted_out

    def _progress_callback(self, complete, total):
        """
        Callback to display progress while uploading to S3

        @return The calculated percentage transferred. Only really used for testing.
        """
        log.debug("Calculating total. Amount complete=%f, total=%f" % (complete, total))
        percent = int(complete * 100.0 / total)
        log.info("Upload completion: {}%".format(percent))
        return percent

    def upload(self, key_name, file_name, cb=True):
        """
        Upload a file to the bucket

        @param string key_name - Key of the file to upload
        """
        log.debug("Uploading file %s to S3 under key %s" % (file_name, key_name))
        key = Key(self.bucket, key_name)
        key.encrypted = True
        upload_kwargs = {}
        if cb:
            upload_kwargs = dict(cb=self._progress_callback, num_cb=10)
        key.set_contents_from_filename(file_name, **upload_kwargs)
        log.debug("Upload complete. Marking object private")
        key.set_acl("private")

    def ls(self):
        "List all keys in the bucket"
        return [{
            'name': key.name, 'size':
            key.size, 'last_modified':
            key.last_modified} for key in self.bucket.get_all_keys()]

    def get_to_file(self, key, path):
        """
        Retrieve a specific object and write it to the given path

        @param key: The key of the object to retrieve
        @param path: Where to write the file to
        """
        log.debug("Retreiving key '%s' from bucket '%s'" % (key, self.bucket))
        key = Key(self.bucket, key)
        log.debug("Writing to file '%s'" % path)
        key.get_contents_to_filename(path)
        log.debug("File written")

    def delete(self, key_name):
        """
        Delete an object from the bucket

        @param string key_name - Key of the object to delete
        """
        key = Key(self.bucket, key_name)
        return self.bucket.delete_key(key)


class GlacierBackend:
    """
    Backend to handle Glacier upload/download (modified from bakthat)
    """
    def __init__(self, access_key, secret_key, vault_name, region_name):
        log.info("Connecting to Amazon Glacier...")
        conn = boto.connect_glacier(aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, region_name=region_name)
        log.info("Connection established.")

        self.vault_name = vault_name

        log.info("Creating vault '%s' if it doesn't exist (nothing will be done if it does)" % vault_name)
        self.vault = conn.create_vault(vault_name)
        log.info("Vault creation request complete.")

    def upload(self, file_name):
        """
        Backup the file and return the archive ID.

        @param string file_name - Full path to the file to backup
        @return string - AWS archive ID for the file
        """
        log.info("Uploading file '%s' to Glacier" % file_name)

        max_retries = 5
        attempt = 1

        while(True):
            try:
                # set the description to an empty string
                return self.vault.concurrent_create_archive_from_file(filename=file_name, description='')
            except UploadArchiveError as e:
                if attempt >= max_retries:
                    log.error("Tried and failed to upload file '%s' %d times." % (file_name, attempt))
                    raise e

                log.info("Received error while trying to upload '%s' to glacier. Will "
                         "retry %d more times after sleeping a while..." % (file_name, max_retries-attempt))

                attempt += 1

                # exponential back-off on failure
                sleep(2**attempt)

    #    def download(self, keyname):
    #        """
    #        Initiate a Job, check its status, and download the archive if it's completed.
    #        """
    #        archive_id = self.get_archive_id(keyname)
    #        if not archive_id:
    #            return
    #
    #        with glacier_shelve() as d:
    #            if not d.has_key("jobs"):
    #                d["jobs"] = dict()
    #
    #            jobs = d["jobs"]
    #            job = None
    #
    #            if keyname in jobs:
    #                # The job is already in shelve
    #                job_id = jobs[keyname]
    #                try:
    #                    job = self.vault.get_job(job_id)
    #                except UnexpectedHTTPResponseError: # Return a 404 if the job is no more available
    #                    del job[keyname]
    #
    #            if not job:
    #                # Job initialization
    #                job = self.vault.retrieve_archive(archive_id)
    #                jobs[keyname] = job.id
    #                job_id = job.id
    #
    #            # Commiting changes in shelve
    #            d["jobs"] = jobs
    #
    #        log.info("Job {action}: {status_code} ({creation_date}/{completion_date})".format(**job.__dict__))
    #
    #        if job.completed:
    #            log.info("Downloading...")
    #            encrypted_out = tempfile.TemporaryFile()
    #            encrypted_out.write(job.get_output().read())
    #            encrypted_out.seek(0)
    #            return encrypted_out
    #        else:
    #            log.info("Not completed yet")
    #            return None
    #
    def create_inventory_retrieval_job(self, sns_topic=None):
        """
        Initiate a job to retrieve the Glacier inventory.

        @param string sns_topic - The Amazon SNS topic ARN where Amazon Glacier sends notification when the job is
            completed and the output is ready to download.
        """
        log.debug("Creating job to retrieve glacier inventory for vault '%s' notifying to SNS topic '%s'" % (self.vault_name, sns_topic))
        return self.vault.retrieve_inventory(sns_topic=sns_topic, description="IceIt inventory retrieval job")

    def list_jobs(self):
        """
        List the status of jobs associated with this vault

        @:return: list of boto.glacier.job.Job objects
        """
        log.debug("Listing jobs associated with vault '%s'" % self.vault_name)
        return self.vault.list_jobs()

#
#    def retrieve_archive(self, archive_id, jobid):
#        """
#        Initiate a job to retrieve Glacier archive or download archive
#        """
#        if jobid is None:
#            return self.vault.retrieve_archive(archive_id, sns_topic=None, description='Retrieval job')
#        else:
#            return self.vault.get_job(jobid)
#
#    def delete(self, keyname):
#        archive_id = self.get_archive_id(keyname)
#        if archive_id:
#            self.vault.delete_archive(archive_id)
#            with glacier_shelve() as d:
#                archives = d["archives"]
#
#                if keyname in archives:
#                    del archives[keyname]
#
#                d["archives"] = archives
#
#            self.backup_inventory()

