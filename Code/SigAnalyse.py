import re
import pytsk3
import sqlite3


class Analyse():
    def __init__(self, image, offset):
        self.disk_image = pytsk3.Img_Info(image)
        self.partitions = pytsk3.Volume_Info(self.disk_image)
        self.offset = offset
        self.ext_pattern = r"(\.)(.*)"
        self.extension = ""
        self.fs_sig = ""

    def sig_find(self, filename):
        file_sys = pytsk3.FS_Info(self.disk_image, self.offset)
        root_dir = file_sys.open_dir("/")
        for fs_obj in root_dir:
            if fs_obj.info.meta is not None:
                if fs_obj.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                    if fs_obj.info.name.name.decode("ascii") == filename:
                        extension_regex = re.compile(self.ext_pattern)
                        extension_match = extension_regex.search(fs_obj.info.name.name.decode("ascii").lower())
                        if extension_match is not None:
                            self.extension = extension_match.group(2)

                            connection = sqlite3.connect("Signatures.db")
                            cursor = connection.cursor()

                            querySelect = "SELECT * FROM Main"
                            queryWhere = " WHERE " + " Extension " + " = " + "'" + self.extension.upper() + "'"
                            query = querySelect + queryWhere
                            cursor.execute(query)
                            result = cursor.fetchall()

                            for r in result:
                                self.fs_sig = r[0]

                            file_sig_regex = re.compile("^" + self.fs_sig, re.DOTALL)
                            file_bytes = fs_obj.read_random(0, fs_obj.info.meta.size)
                            sig_match = file_sig_regex.search(file_bytes.decode('latin-1'))

                            if sig_match is not None:
                                return True
                            else:
                                return False
