import sqlite3
import pytsk3
import pyewf
from E01_Handler import E01Handler
from RegistryAnalyse import RegGet
import os
from datetime import datetime
import hashlib


class PytskInfo():
    def __init__(self, file, imgtype):
        if imgtype == "E01":
            filenames = pyewf.glob(file)
            self.ewf_handle = pyewf.handle()
            self.ewf_handle.open(filenames)
            self.IsE01 = True
            self.img_info = E01Handler(self.ewf_handle)
            self.vol_info = pytsk3.Volume_Info(self.img_info)
            self.file = file
        else:
            self.IsE01 = False
            self.img_info = pytsk3.Img_Info(file)
            self.vol_info = pytsk3.Volume_Info(self.img_info)
            self.file = file

        self.connection = object
        self.cursor = object
        self.LogDirectory = ""
        self.start_offsets = []
        self.failed_fs = []
        self.fs_sizes = []
        self.working_offsets = []
        self.directories = []
        self.files = []
        self.root_files = []
        self.root_dirs = []

    def sql_setup(self):
        try:
            dirname = "APDF Log"
            cwd = os.getcwd()
            path = os.path.join(cwd, dirname)
            os.mkdir(path)
            self.LogDirectory = path
        except:
            dirname = "APDF Log"
            path = os.getcwd() + "\\" + dirname
            self.LogDirectory = path

        self.connection = sqlite3.connect("APDF Log\\APDF report.db")
        self.cursor = self.connection.cursor()

        basic_command = """
        CREATE TABLE BasicInfo (
        File TEXT,
        ByteSize INTEGER,
        Sectors REAL,
        Allocated REAL,
        Unallocated REAL,
        CaseNum VARCHAR,
        EvidenceNum VARCHAR,
        ExaminerName TEXT,
        Hash VARCHAR);"""

        part_command = """
        CREATE TABLE Partitions (
        Count INTEGER, 
        Type VARCHAR, 
        Start INTEGER,
        Offset INTEGER, 
        Sectors INTEGER,
        Scheme TEXT);"""

        filesys_command = """
        CREATE TABLE FileSystems (
        Count INTEGER, 
        Type VARCHAR, 
        Clusters INTEGER, 
        ClusterSize INTEGER, 
        Endianness INTEGER, 
        MetaRecords INTEGER, 
        Flags INTEGER, 
        RootInum INTEGER);"""

        root_command = """
        CREATE TABLE RootDirectory (
        FileSys TEXT,
        Name VARCHAR,  
        FoundIn VARCHAR,
        Type VARCHAR);"""

        rootMeta_command = """
        CREATE TABLE RootMeta (
        Name VARCHAR, 
        Type VARCHAR, 
        MetaRecordNum INTEGER,
        AccessTime INTEGER,
        CreateTime INTEGER,
        ModifiedTime INTEGER,
        MetaChangeTime INTEGER,
        OwnerGID INTEGER,
        Size INTEGER,
        Deleted VARCHAR,
        ParentDirectory TEXT);"""

        hash_command = """
        CREATE TABLE FileHashes (
        FileSys TEXT,
        FileName TEXT,
        Match TEXT,
        Hash VARCHAR);"""

        self.cursor.execute(part_command)
        self.cursor.execute(filesys_command)
        self.cursor.execute(root_command)
        self.cursor.execute(rootMeta_command)
        self.cursor.execute(basic_command)
        self.cursor.execute(hash_command)

    def basic_info(self):
        size = self.img_info.get_size()
        unallocated = 0
        for volume in self.vol_info:
            if volume.desc.decode("ascii") == "Unallocated":
                unallocated += volume.len
            else:
                pass
        sectors = size/512
        allocated = (size/512)-unallocated
        unallocated = unallocated/512
        na = "N/A"

        if self.IsE01 is True:
            ls = self.img_info.case_info(self.ewf_handle)
            casenum = (ls[0])
            evidencenum = str(ls[1])
            name = str(ls[2])
            filehash = str(ls[3]).replace("{", "")
            filehash.replace("}", "")

            data_tuple = (self.file, size, sectors, allocated, unallocated, casenum, evidencenum, name, filehash)

        else:
            data_tuple = (self.file, size, sectors, allocated, unallocated, "N/A", "N/A", "N/A", "N/A")

        sql_command = """
        INSERT INTO BasicInfo (File, ByteSize, Sectors, Allocated, Unallocated, CaseNum, EvidenceNum, ExaminerName, Hash)
        VALUES (?,?,?,?,?,?,?,?,?);"""

        self.cursor.execute(sql_command, data_tuple)
        self.connection.commit()

        return data_tuple

    def partitions(self):
        if self.vol_info.info.vstype == pytsk3.TSK_VS_TYPE_DOS:
            part_scheme = "MBR"
        else:
            part_scheme = "GPT"

        count = 0
        for volume in self.vol_info:
            count += 1
            type = volume.desc.decode("ascii")
            start = volume.start
            offset = start * 512
            sectors = volume.len

            self.start_offsets.append(offset)

            sql_command = """
            INSERT INTO Partitions (Count, Type, Start, Offset, Sectors, Scheme)
            VALUES (?,?,?,?,?,?);"""

            data_tuple = (count, type, start, offset, sectors, part_scheme)

            self.cursor.execute(sql_command, data_tuple)
            self.connection.commit()

        data_tuple = (count, type, start, offset, sectors, part_scheme)
        return data_tuple

    def file_systems(self):
        count = 0
        for offset in self.start_offsets:
            count += 1
            try:
                fs_info = pytsk3.FS_Info(self.img_info, offset)
                fs_type = fs_info.info.ftype
                if fs_type == pytsk3.TSK_FS_TYPE_NTFS:
                    type = "NTFS"
                elif fs_type == pytsk3.TSK_FS_TYPE_FAT32:
                    type = "FAT32"
                elif fs_type == pytsk3.TSK_FS_TYPE_APFS:
                    type = "APFS"
                elif fs_type == pytsk3.TSK_FS_TYPE_EXFAT:
                    type = "EXFAT"
                elif fs_info == pytsk3.TSK_FS_TYPE_HFS:
                    type = "HFS"

                ClusterCount = fs_info.info.block_count
                ClusterSize = fs_info.info.block_size
                EndianOrder = fs_info.info.endian
                MetaRecords = fs_info.info.inum_count
                Flags = fs_info.info.flags
                Root = fs_info.info.root_inum
                fs_size = fs_info.info.block_count + fs_info.info.block_size
                self.fs_sizes.append(fs_size)

                sql_command = """
                INSERT INTO FileSystems (Count, Type, Clusters, ClusterSize, Endianness, MetaRecords, Flags, RootInum)
                VALUES (?,?,?,?,?,?,?,?);"""

                data_tuple = (count, type, ClusterCount, ClusterSize, EndianOrder, MetaRecords, Flags, Root)

                self.cursor.execute(sql_command, data_tuple)
                self.connection.commit()
                self.working_offsets.append(offset)

            except:
                sql_command = """
                INSERT INTO FileSystems (Count, Type, Clusters, ClusterSize, Endianness, MetaRecords, Flags, RootInum)
                VALUES (?,?,?,?,?,?,?,?);"""

                data_tuple = (count, "Empty", "Empty", "Empty", "Empty", "Empty", "Empty", "Empty")

                self.cursor.execute(sql_command, data_tuple)
                self.connection.commit()
                self.failed_fs.append(offset)

    def all_file_analysis(self):
        for offset in self.working_offsets:
            fs_info = pytsk3.FS_Info(self.img_info, offset)
            root_dir = fs_info.open_dir(inode=fs_info.info.root_inum)
            dir_count = 0
            file_count = 0
            file_in_dir = 0
            for file in root_dir:
                if file.info.meta != None:
                    if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        file_type = "Directory"
                        dir_count += 1
                        file_in_dir += 1
                        ascii_name = file.info.name.name.decode("ascii")
                        self.directories.append(ascii_name)
                        self.root_dirs.append(ascii_name)
                        sql_command = """
                        INSERT INTO RootDirectory (FileSys, Name, FoundIn, Type)
                        VALUES (?,?,?,?);"""

                        data_tuple = (offset, ascii_name, "Root", file_type)

                        self.cursor.execute(sql_command, data_tuple)
                        self.connection.commit()

                        directory = "/" + ascii_name
                        dir = fs_info.open_dir(directory)
                        for file in dir:
                            if file.info.meta != None:
                                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                                    file_type = "Directory"
                                    dir_count += 1
                                    file_in_dir += 1
                                    ascii_name = file.info.name.name.decode("ascii")
                                    self.directories.append(ascii_name)
                                    sql_command = """
                                    INSERT INTO RootDirectory (FileSys, Name, FoundIn, Type)
                                    VALUES (?,?,?,?);"""

                                    data_tuple = (offset, ascii_name, directory, file_type)

                                    self.cursor.execute(sql_command, data_tuple)
                                    self.connection.commit()

                                else:
                                    file_type = "File"
                                    file_count += 1
                                    ascii_name = file.info.name.name.decode("ascii")
                                    self.files.append(ascii_name)

                                    sql_command = """
                                                       INSERT INTO RootDirectory (FileSys,Name,FoundIn,Type)
                                                       VALUES (?,?,?,?);"""

                                    data_tuple = (offset, ascii_name, directory, file_type)

                                    self.cursor.execute(sql_command, data_tuple)
                                    self.connection.commit()

                    else:
                        file_type = "File"
                        file_count += 1
                        ascii_name = file.info.name.name.decode("ascii")
                        self.files.append(ascii_name)
                        self.root_files.append(ascii_name)

                        sql_command = """
                        INSERT INTO RootDirectory (FileSys,Name,FoundIn,Type)
                        VALUES (?,?,?,?);"""

                        data_tuple = (offset, ascii_name, "Root", file_type)

                        self.cursor.execute(sql_command, data_tuple)
                        self.connection.commit()

    def all_meta(self):
        for offset in self.working_offsets:
            fs_info = pytsk3.FS_Info(self.img_info, offset)
            root_dir = fs_info.open_dir(inode=fs_info.info.root_inum)
            for file in root_dir:
                if file.info.meta != None:
                    if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:

                        ascii_name = file.info.name.name.decode("ascii")
                        directory = "/" + ascii_name
                        dir = fs_info.open_dir(directory)

                        for file in dir:
                            if file.info.meta != None:
                                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                                    pass

                                else:
                                    parent_dir = directory
                                    file_meta = file.info.meta
                                    file_name = file.info.name
                                    ascii_name = file_name.name.decode("ascii")
                                    acc_time = datetime.utcfromtimestamp(file_meta.atime)
                                    crt_time = datetime.utcfromtimestamp(file_meta.crtime)
                                    meta_time = datetime.utcfromtimestamp(file_meta.ctime)
                                    mod_time = datetime.utcfromtimestamp(file_meta.mtime)
                                    type = file_name.type
                                    MetaAddr = file_meta.addr
                                    ownergid = file_meta.gid
                                    size = file_meta.size
                                    if file_meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                                        deleted = "Yes"
                                    else:
                                        deleted = "No"

                                    sql_command = """
                                    INSERT INTO RootMeta (Name, Type, MetaRecordNum, AccessTime, CreateTime, ModifiedTime, MetaChangeTime, OwnerGID, Size, Deleted, ParentDirectory)
                                    VALUES (?,?,?,?,?,?,?,?,?,?,?);"""

                                    data_tuple = (ascii_name, type, MetaAddr, acc_time, crt_time, mod_time, meta_time, ownergid, size, deleted, parent_dir)

                                    self.cursor.execute(sql_command, data_tuple)
                                    self.connection.commit()

                    else:
                        parent_dir = "Root"
                        file_meta = file.info.meta
                        file_name = file.info.name
                        ascii_name = file_name.name.decode("ascii")
                        acc_time = datetime.utcfromtimestamp(file_meta.atime)
                        crt_time = datetime.utcfromtimestamp(file_meta.crtime)
                        meta_time = datetime.utcfromtimestamp(file_meta.ctime)
                        mod_time = datetime.utcfromtimestamp(file_meta.mtime)
                        type = file_name.type
                        MetaAddr = file_meta.addr
                        ownergid = file_meta.gid
                        size = file_meta.size
                        if file_meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                            deleted = "Yes"
                        else:
                            deleted = "No"

                        sql_command = """
                               INSERT INTO RootMeta (Name, Type, MetaRecordNum, AccessTime, CreateTime, ModifiedTime, MetaChangeTime, OwnerGID, Size, Deleted, ParentDirectory)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?);"""

                        data_tuple = (ascii_name, type, MetaAddr, acc_time, crt_time, mod_time, meta_time, ownergid, size, deleted, parent_dir)

                        self.cursor.execute(sql_command, data_tuple)
                        self.connection.commit()

    def hash_files(self, user_hash):
        for offset in self.working_offsets:
            fs_info = pytsk3.FS_Info(self.img_info, offset)
            root = fs_info.open_dir(inode=fs_info.info.root_inum)
            for file in root:
                if file.info.meta != None:
                    if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        ascii_name = file.info.name.name.decode("ascii")
                        directory = "/" + ascii_name
                        dir = fs_info.open_dir(directory)

                        for file in dir:
                            if file.info.meta != None:
                                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                                    pass
                                else:
                                    ascii_name = file.info.name.name.decode("ascii")
                                    file_meta = file.info.meta
                                    file_size = file_meta.size
                                    chunk_size = 1024
                                    offset = 0
                                    md5_hash = hashlib.md5()

                                    while file_size > 0:
                                        data = file.read_random(offset, min(chunk_size, file_size))
                                        md5_hash.update(data)
                                        offset +=  chunk_size
                                        file_size -= chunk_size

                                    hashVal = md5_hash.hexdigest().upper()

                                    if md5_hash.hexdigest().upper() == user_hash:
                                        match = "Yes"
                                    else:
                                        match = "No"

                                    sql_command = """
                                       INSERT INTO FileHashes (Filesys, FileName, Hash, Match)
                                       VALUES (?,?,?,?);"""

                                    data_tuple = (offset, ascii_name, str(hashVal), match)

                                    self.cursor.execute(sql_command, data_tuple)
                                    self.connection.commit()

                    else:
                        ascii_name = file.info.name.name.decode("ascii")
                        file_meta = file.info.meta
                        file_size = file_meta.size
                        chunk_size = 1024
                        offset = 0
                        md5_hash = hashlib.md5()

                        while file_size > 0:
                            data = file.read_random(offset, min(chunk_size, file_size))
                            md5_hash.update(data)
                            offset += chunk_size
                            file_size -= chunk_size

                        hashVal = md5_hash.hexdigest().upper()

                        if md5_hash.hexdigest().upper() == user_hash:
                            match = "Yes"
                        else:
                            match = "No"

                        sql_command = """
                           INSERT INTO FileHashes (Filesys, FileName, Hash, Match)
                           VALUES (?,?,?,?);"""

                        data_tuple = (offset, ascii_name, str(hashVal), match)

                        self.cursor.execute(sql_command, data_tuple)
                        self.connection.commit()

    def main(self):
        self.sql_setup()
        self.basic_info()
        self.partitions()
        self.file_systems()
        self.all_file_analysis()
        self.all_meta()
