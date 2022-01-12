import pytsk3
import os
from Extensions import GetExt


class FileCarving():
    def __init__(self, evidence_name, offset):
        self.evidence_file = evidence_name
        self.img_info = pytsk3.Img_Info(evidence_name)
        self.offset = int(offset)
        self.filesystemfiles = ["$AttrDef", "$BadClus", "$Bitmap", "$Boot", "$FAT1", "$FAT2", "$I30", "$LogFile",
                                "$MBR", "$MFT", "$MTFMirr", "$Objld", "$OrphanFiles", "%Quota", "$Reparse", "$Volume",
                                "$Secure", "$UpCase"]

    def carve_all(self):
        try:
            dirname = f"{self.evidence_file} - All Carved files"
            path = os.path.join("APDF Log", dirname)
            os.mkdir(path)
        except:
            dirname = "APDF Log"
            path = os.getcwd() + "\\" + dirname

        filesys = pytsk3.FS_Info(self.img_info, self.offset)

        root_dir = filesys.open_dir(inode=filesys.info.root_inum)

        for file in root_dir:
            if file.info.meta is not None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    ascii_name = file.info.name.name.decode("ascii")
                    directory = "/" + ascii_name
                    dir = filesys.open_dir(directory)

                    for file in dir:
                        if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            pass

                        else:
                            try:
                                ascii_name = file.info.name.name.decode("ascii")
                                file = filesys.open(ascii_name)
                                filebytes = file.read_random(0, file.info.meta.size)
                                extension = GetExt(ascii_name)
                                if extension.get() is None:
                                    ext = ""
                                else:
                                    ext = extension.get()

                                carvedname = f"{path}/Carved file - {ascii_name} from {self.offset}{ext}"
                                f = open(carvedname, "wb")
                                f.write(filebytes)
                                f.close()
                            except:
                                pass

                else:
                    try:
                        ascii_name = file.info.name.name.decode("ascii")
                        file = filesys.open(ascii_name)
                        filebytes = file.read_random(0, file.info.meta.size)
                        extension = GetExt(ascii_name)
                        if extension.get() is None:
                            ext = ""
                        else:
                            ext = extension.get()

                        carvedname = f"{path}/Carved file - {ascii_name} from {self.offset}{ext}"
                        f = open(carvedname, "wb")
                        f.write(filebytes)
                        f.close()
                    except:
                        pass

    def carve_system(self):
        dirname = f"{self.evidence_file} - Carved system files"
        try:
            path = os.path.join("APDF Log", dirname)
            os.mkdir(path)
        except:
            dirname = "APDF Log"
            path = os.getcwd() + "\\" + dirname

        filesys = pytsk3.FS_Info(self.img_info, self.offset)

        root_dir = filesys.open_dir(inode=filesys.info.root_inum)

        for file in root_dir:
            if file.info.meta is not None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    ascii_name = file.info.name.name.decode("ascii")
                    directory = "/" + ascii_name
                    dir = filesys.open_dir(directory)

                    for file in dir:
                        if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            pass

                        else:
                            try:
                                ascii_name = file.info.name.name.decode("ascii")
                                for sysfile in self.filesystemfiles:
                                    if ascii_name == sysfile:
                                        file = filesys.open(ascii_name)
                                        filebytes = file.read_random(0, file.info.meta.size)
                                        extension = GetExt(ascii_name)
                                        if extension.get() is None:
                                            ext = ""
                                        else:
                                            ext = extension.get()

                                        carvedname = f"{path}/Carved file - {ascii_name} from {self.offset}{ext}"
                                        f = open(carvedname, "wb")
                                        f.write(filebytes)
                                        f.close()
                                    else:
                                        pass
                            except:
                                pass

                else:
                    try:
                        ascii_name = file.info.name.name.decode("ascii")
                        for sysfile in self.filesystemfiles:
                            if ascii_name == sysfile:
                                file = filesys.open(ascii_name)
                                filebytes = file.read_random(0, file.info.meta.size)
                                extension = GetExt(ascii_name)
                                if extension.get() is None:
                                    ext = ""
                                else:
                                    ext = extension.get()

                                carvedname = f"{path}/Carved file - {ascii_name} from {self.offset}{ext}"
                                f = open(carvedname, "wb")
                                f.write(filebytes)
                                f.close()
                            else:
                                pass
                    except:
                        pass

    def carve_type(self, file_type):
        try:
            ftype = str(file_type).replace(".", "")
        except:
            pass

        try:
            dirname = f"{self.evidence_file} - Carved {ftype} files"
            path = os.path.join("APDF Log", dirname)
            os.mkdir(path)
        except:
            dirname = "APDF Log"
            path = os.getcwd() + "\\" + dirname

        filesys = pytsk3.FS_Info(self.img_info, self.offset)

        root_dir = filesys.open_dir(inode=filesys.info.root_inum)

        for file in root_dir:
            if file.info.meta is not None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    ascii_name = file.info.name.name.decode("ascii")
                    directory = "/" + ascii_name
                    dir = filesys.open_dir(directory)

                    for file in dir:
                        if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            pass

                        else:
                            try:
                                ascii_name = file.info.name.name.decode("ascii")
                                file = filesys.open(ascii_name)
                                filebytes = file.read_random(0, file.info.meta.size)
                                extension = GetExt(ascii_name)
                                if extension.get() is None:
                                    ext = None
                                else:
                                    ext = extension.get()

                                if str(ext) == file_type:
                                    carvedname = f"{path}/Carved file - {ascii_name} from {self.offset}{ext}"
                                    f = open(carvedname, "wb")
                                    f.write(filebytes)
                                    f.close()

                            except:
                                pass

                else:
                    try:
                        ascii_name = file.info.name.name.decode("ascii")
                        file = filesys.open(ascii_name)
                        filebytes = file.read_random(0, file.info.meta.size)
                        extension = GetExt(ascii_name)
                        if extension.get() is None:
                            ext = None
                        else:
                            ext = extension.get()

                        if str(ext) == file_type:
                            carvedname = f"{path}/Carved file - {ascii_name} from {self.offset}{ext}"
                            f = open(carvedname, "wb")
                            f.write(filebytes)
                            f.close()

                    except:
                        pass

    def carve_specific(self, file_to_carve):
        try:
            dirname = f"{self.evidence_file} - Specific Carved files"
            path = os.path.join("APDF Log", dirname)
            os.mkdir(path)
        except:
            dirname = "APDF Log"
            path = os.getcwd() + "\\" + dirname

        filesys = pytsk3.FS_Info(self.img_info, self.offset)

        root_dir = filesys.open_dir(inode=filesys.info.root_inum)

        for file in root_dir:
            if file.info.meta is not None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    ascii_name = file.info.name.name.decode("ascii")
                    directory = "/" + ascii_name
                    dir = filesys.open_dir(directory)

                    for file in dir:
                        if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            pass

                        else:
                            try:
                                ascii_name = file.info.name.name.decode("ascii")
                                file = filesys.open(ascii_name)
                                filebytes = file.read_random(0, file.info.meta.size)
                                extension = GetExt(ascii_name)
                                if extension.get() is None:
                                    ext = None
                                else:
                                    ext = extension.get()

                                if str(ascii_name).lower() == str(file_to_carve).lower():
                                    carvedname = f"{path}/Carved file - {ascii_name} from {self.offset}{ext}"
                                    f = open(carvedname, "wb")
                                    f.write(filebytes)
                                    f.close()

                            except:
                                pass

                else:
                    try:
                        ascii_name = file.info.name.name.decode("ascii")
                        file = filesys.open(ascii_name)
                        filebytes = file.read_random(0, file.info.meta.size)
                        extension = GetExt(ascii_name)
                        if extension.get() is None:
                            ext = None
                        else:
                            ext = extension.get()

                        if str(ascii_name).lower() == str(file_to_carve).lower():
                            carvedname = f"{path}/Carved file - {ascii_name} from {self.offset}{ext}"
                            f = open(carvedname, "wb")
                            f.write(filebytes)
                            f.close()

                    except:
                        pass
