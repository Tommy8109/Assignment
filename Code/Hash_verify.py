import hashlib


class HashVerify():
    def __init__(self):
        """Setting up the instance variable for the file hash"""
        self.file_hash = ""

    def verify(self, file, hash, algorithm):
        """
        verify takes 3 arguments. The first is the name of the file to check,
        the second is a user input hash to check against and the third is to
        dictate what hash algorithm to use, MD5 or sha256
        """
        with open(file, "rb") as f:
            bytes = f.read()

            if str(algorithm).lower() == "sha256":
                readable_hash = hashlib.sha256(bytes).hexdigest()
            else:
                readable_hash = hashlib.md5(bytes).hexdigest()

            self.file_hash = readable_hash

        if self.file_hash == str(hash).lower():
            return True

        else:
            return False
