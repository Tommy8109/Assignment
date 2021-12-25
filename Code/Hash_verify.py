import hashlib
import pytsk3

class HashVerify():
    def __init__(self, diskimage, offset):
        """Setting up the instance variable for the file hash"""
        self.file_hash = ""
        self.diskimage = diskimage
        self.offset = offset

    def md5_compare(self, filename, user_hash):
        """
        Method - hash_compare
        ----------------------
        Purpose - This functions purpose is to verify the files hash,
        to make sure it hasn't been changed. It will read the file
        in chunks as its safer.

        :param filename: The name of the file to verify
        :param user_hash: The Hash to compare against
        :return: Returns True or False depending on if hash matches
        """

        partition = pytsk3.FS_Info(self.diskimage, self.offset)
        file_obj = partition.open(filename)
        file_meta = file_obj.info.meta
        file_size = file_meta.size
        chunk_size = 1024
        offset = 0
        md5_hash = hashlib.md5()

        while file_size > 0:
            data = file_obj.read_random(offset, min(chunk_size, file_size))
            md5_hash.update(data)
            offset += chunk_size
            file_size -= chunk_size
        if md5_hash.hexdigest().upper() == user_hash:
            return True
        else:
            return False

    def sha_compare(self, filename, user_hash):
        partition = pytsk3.FS_Info(self.diskimage, self.offset)
        file_obj = partition.open(filename)
        file_meta = file_obj.info.meta
        file_size = file_meta.size
        chunk_size = 1024
        offset = 0
        sha_hash = hashlib.sha256()

        while file_size > 0:
            data = file_obj.read_random(offset, min(chunk_size, file_size))
            sha_hash.update(data)
            offset += chunk_size
            file_size -= chunk_size

        if sha_hash.hexdigest().upper() == user_hash:
            return True
        else:
            return False
