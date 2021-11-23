import pytsk3
from datetime import datetime
from Reports import MakeReport
from Exif_reader import ExifTags
import hashlib
import os

class Decode():
    def __init__(self):
        """Creating the disk image variable which is equivalent to f=open()"""
        self.diskimage = object
        self.volume_info = object
        self.start_offsets = []
        self.fs_sizes = []
        self.failed_fs = []
        self.chosen_file = ""

        self.report_partition = "Partition Report.csv"
        self.report_fs = "FS Report.csv"
        self.report_files = "Found file report.csv"

        self.chosen_offset = ""
        self.file_pattern = r"(?P<Name>\w+)\.(?P<Extension>\w+)"
        self.img_formats = ["JPEG", "JPG", "PNG", "GIF", "TIFF", "PSD"]
        self.file_list = []
        self.meta_records = []
        self.dir_names = []
        self.file_count = int

    def general_info(self):
        """
        Prints out general information about the image file chosen.
        Gets called on the main menu when option 1 is selected.
        """
        byte_size = self.diskimage.get_size()
        unallocated = 0
        for volume in self.volume_info:
            if volume.desc.decode("ascii") == "Unallocated":
                unallocated += volume.len

            else:
                pass

        print(f"File name: {self.chosen_file}")
        print(f"Image size in bytes: {byte_size}")
        print(f"Image size in MB: {round(byte_size/10000,2)}")
        print(f"Sector count: {round(byte_size/512,0)}")
        print(f"Allocated space(sectors): {round((byte_size/512)-(unallocated/512),0)}")
        print(f"Unallocated space (sectors): {round(unallocated/512,0)}")

    def partition_table(self):
        """
        Uses the self.volume_info variable to retrieve information about
        each partition and output it to the terminal as well as a CSV file
        via Report class. It finds the layout, type, start offset and size.
        """
        if self.volume_info.info.vstype == pytsk3.TSK_VS_TYPE_GPT:
            print("This volume uses GPT scheme")
        elif self.volume_info.info.vstype == pytsk3.TSK_VS_TYPE_DOS:
            print("This volume uses MBR")

        print("There are", self.volume_info.info.part_count, "partitions in this image")

        count = 0
        for volume in self.volume_info:
            count += 1
            print("Partition number: ", count)
            print("Partition type: ", volume.desc.decode("ascii"))
            print("Start LBA: ", volume.start)
            print("Number of sectors: ", volume.len)
            print("")
            self.start_offsets.append(volume.start * 512)
            report = MakeReport()
            report.partition_report(count, volume.desc.decode("ascii"), volume.start, volume.len)

    def image_exif(self, file):
        print(f"{file} Image information:")
        exif = ExifTags()
        exif.read_image_tags(file)
        exif.read_gps_tags(file)

    def file_sys_analysis(self):
        """
        Code for decoding the file systems found within the image
        For each offset stored in self.start_offsets it gathers the
        file system in use (NTFS, FAT, etc), the number of clusters,
        size of clusters, endian order, metadata records and flags.
        This is all then passed to the report class to output to CSV
        """

        failed_offsets = []
        count = 0
        for partition_offset in self.start_offsets:
            try:
                fs_info = pytsk3.FS_Info(self.diskimage, partition_offset)
                fs_type = fs_info.info.ftype
                if fs_type == pytsk3.TSK_FS_TYPE_NTFS:
                    print("File system in use: NTFS")
                elif fs_type == pytsk3.TSK_FS_TYPE_FAT32:
                    print("File system in use: FAT32")
                elif fs_type == pytsk3.TSK_FS_TYPE_EXFAT:
                    print("File system in use: EXFAT")
                elif fs_type == pytsk3.TSK_FS_TYPE_FAT16:
                    print("File system in use: FAT16")

                print(f"Number of clusters: {fs_info.info.block_count}")
                print(f"Cluster size: {fs_info.info.block_size}")
                print(f"File system endian order: {fs_info.info.endian}")
                print(f"Metadata records available: {fs_info.info.inum_count}")
                print(f"File system flags: {fs_info.info.flags}")
                print(f"Root inum: {fs_info.info.root_inum}")
                print("")
                fs_size = fs_info.info.block_count + fs_info.info.block_size
                self.fs_sizes.append(fs_size)

                report = MakeReport()
                report.file_sys_report(fs_type, fs_info.info.block_count, fs_info.info.block_size,
                                       fs_info.info.endian, fs_info.info.inum_count, fs_info.info.flags)

            except:
                self.failed_fs.append(partition_offset)
                count += 1

        print(f"Failed to decode {count} partitions at offsets: ")
        for offset in failed_offsets:
            print(offset)

        prompt = input("View a file system in more depth?\n")
        if prompt.lower() == "yes":
            self.fs_first_menu()

    def root_analysis(self, offset):
        fs_info = pytsk3.FS_Info(self.diskimage, offset)
        root_dir = fs_info.open_dir(inode=fs_info.info.root_inum)
        dir_count = 0
        file_count = 0
        file_in_dir = 0
        for file in root_dir:
            if file.info.meta != None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    file_type_str = "Dir"
                    dir_count += 1
                    file_in_dir += 1
                    ascii_name = file.info.name.name.decode("ascii")
                    self.dir_names.append(ascii_name)
                else:
                    file_count += 1
                    file_type_str = 'File'
                    ascii_name = file.info.name.name.decode("ascii")
                    self.file_list.append(ascii_name)

        print(f"Directories: {dir_count}   Files in directories {file_in_dir}    Root files: {file_count}")
        print("-" * 80)
        print("Directories found")
        print("-"*20)
        for dir in self.dir_names:
            print(f"Directory found: {dir}")
        print("")
        print("Files found")
        print("-" * 20)
        for file in self.file_list:
            print(f"File found: {file}")
        print("")

    def file_analysis(self, offset):
        partition = pytsk3.FS_Info(self.diskimage, offset)
        deleted_count = 0
        for file in self.file_list:
            file_obj = partition.open(file)
            file_meta = file_obj.info.meta
            file_name = file_obj.info.name
            self.file_count = len(self.file_list)

            acc_time = datetime.utcfromtimestamp(file_meta.atime)
            crt_time = datetime.utcfromtimestamp(file_meta.crtime)
            meta_time = datetime.utcfromtimestamp(file_meta.ctime)
            mod_time = datetime.utcfromtimestamp(file_meta.mtime)

            print(f"Name: {file_name.name}")
            print(f"File type: {file_name.type}")
            print(f"Metadata record number: {file_meta.addr}")
            print(f"Last access time: {acc_time}")
            print(f"Creation time: {crt_time}")
            print(f"Last modified time: {mod_time}")
            print(f"Metadata change time: {meta_time}")
            print(f"Owner group ID: {file_meta.gid}")
            print(f"Size in bytes: {file_meta.size}")
            if file_meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                print("Deleted status: Deleted")
                deleted_count += 0
                status = "Deleted"
            else:
                print("Deleted status: Not deleted")
                status = "Not deleted"
            print("")

            self.meta_records.append(file_meta.addr)

            report = MakeReport()
            report.files_report(file_name.name, file_name.type, file_meta.addr, acc_time, crt_time, mod_time, meta_time,
                                file_meta.gid, file_meta.size, status)

        print(f"Total files analysed: {self.file_count}")
        print(f"Deleted files found: {deleted_count}")
        print("")

    def meta_analysis(self, offset):
        partition = pytsk3.FS_Info(self.diskimage, offset)
        for record in self.meta_records:
            print(record)

    def dir_analysis(self):
        count = 0
        for dir in self.dir_names:
            print(f"{count}) {dir}")
            count += 1

        select_dir = input("Select the directory to view:")
        try:
            fs_info = pytsk3.FS_Info(self.diskimage, self.chosen_offset)
            directory = fs_info.open_dir(select_dir)
        except:
            print(f"Could not open directory {select_dir}")
            self.fs_second_menu(self.chosen_offset)

        dir_count = 0
        file_count = 0
        file_in_dir = 0
        for file in directory:
            if file.info.meta != None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    file_type_str = "Dir"
                    dir_count += 1
                    file_in_dir += 1
                    ascii_name = file.info.name.name.decode("ascii")
                    self.dir_names.append(ascii_name)
                else:
                    file_count += 1
                    file_type_str = 'File'
                    ascii_name = file.info.name.name.decode("ascii")
                    self.file_list.append(ascii_name)

        print(f"Directories: {dir_count}   Files in directories {file_in_dir}    Root files: {file_count}")
        print("-" * 80)
        print("Directories found")
        print("-"*20)
        for dir in self.dir_names:
            print(f"Directory found: {dir}")
        print("")
        print("Files found")
        print("-" * 20)
        for file in self.file_list:
            print(f"File found: {file}")
        print("")

    def hash_compare(self, filename, user_hash):
        # file = example1.py

        partition = pytsk3.FS_Info(self.diskimage, self.chosen_offset)
        file_obj = partition.open(filename)
        file_meta = file_obj.info.meta
        file_size = file_meta.size
        chunk_size = 1024
        offset = 0
        md5_hash = hashlib.md5()

        while file_size > 0:
            data = file_obj.read_random(offset, min(chunk_size, file_size))
            md5_hash.update(data)
            offset +=  chunk_size
            file_size -= chunk_size

        print(f"{filename} has the MD5 hash of: {md5_hash.hexdigest()}")
        if md5_hash.hexdigest().upper() == user_hash:
            return True
        else:
            return False

    def specific_file(self, filename):
        partition = pytsk3.FS_Info(self.diskimage, self.chosen_offset)
        deleted_count = 0
        file_obj = partition.open(filename)
        file_meta = file_obj.info.meta
        file_name = file_obj.info.name

        acc_time = datetime.utcfromtimestamp(file_meta.atime)
        crt_time = datetime.utcfromtimestamp(file_meta.crtime)
        meta_time = datetime.utcfromtimestamp(file_meta.ctime)
        mod_time = datetime.utcfromtimestamp(file_meta.mtime)

        print(f"Name: {file_name.name}")
        print(f"File type: {file_name.type}")
        print(f"Metadata record number: {file_meta.addr}")
        print(f"Last access time: {acc_time}")
        print(f"Creation time: {crt_time}")
        print(f"Last modified time: {mod_time}")
        print(f"Metadata change time: {meta_time}")
        print(f"Owner group ID: {file_meta.gid}")
        print(f"Size in bytes: {file_meta.size}")
        if file_meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
            print("Deleted status: Deleted")
            deleted_count += 0
            status = "Deleted"
        else:
            print("Deleted status: Not deleted")
            status = "Not deleted"
        print("")

    def boot_view(self):
        print("")
        f = open("Session2_Image.001", "rb")
        bytes = 0
        line = []
        filecontents = f.read(512)
        for b in filecontents:
            bytes += 1
            line.append(b)

            print("{0:0{1}x}".format(b, 2), end=" ")

            if bytes % 16 == 0:
                print("#", end="")
                for b2 in line:
                    if (b2 >= 32) and (b2 <= 126):
                        print(chr(b2), end="")
                    else:
                        print("*", end="")
                line = []
                print("")

        print("")

    def fs_view(self, offset):
        print("")
        f = open(self.chosen_file, "rb")
        while True:
            f.seek(offset)
            bytes = 0
            line = []
            filecontents = f.read(512)

            for b in filecontents:
                bytes += 1
                line.append(b)

                print("{0:0{1}x}".format(b, 2), end=" ")

                if bytes % 16 == 0:
                    print("#", end="")
                    for b2 in line:
                        if (b2 >= 32) and (b2 <= 126):
                            print(chr(b2), end="")
                        else:
                            print("*", end="")
                    line = []
                    print("")
            con_prompt = input("Continue?\n")
            if con_prompt.lower() == "yes":
                offset += 512
            else:
                break

            print("")

    def file_view(self, filename):
        partition = pytsk3.FS_Info(self.diskimage, self.chosen_offset)
        file_obj = partition.open(filename)
        file_meta = file_obj.info.meta
        file_size = file_meta.size
        chunk_size = 1024
        offset = 0

        print("")
        while True:
            bytes = 0
            line = []
            filecontents = file_obj.read_random(offset, file_size)

            for b in filecontents:
                bytes += 1
                line.append(b)

                print("{0:0{1}x}".format(b, 2), end=" ")

                if bytes % 16 == 0:
                    print("#", end="")
                    for b2 in line:
                        if (b2 >= 32) and (b2 <= 126):
                            print(chr(b2), end="")
                        else:
                            print("*", end="")
                    line = []
                    print("")

            print("")

    def manual_menu(self, offset):
        print("")
        f = open(self.chosen_file, "rb")
        while True:
            f.seek(offset)
            bytes = 0
            line = []
            filecontents = f.read(512)

            for b in filecontents:
                bytes += 1
                line.append(b)

                print("{0:0{1}x}".format(b, 2), end=" ")

                if bytes % 16 == 0:
                    print("#", end="")
                    for b2 in line:
                        if (b2 >= 32) and (b2 <= 126):
                            print(chr(b2), end="")
                        else:
                            print("*", end="")
                    line = []
                    print("")
            con_prompt = input("Continue?\n")
            if con_prompt.lower() == "yes":
                offset += 512
            else:
                break

            print("")


    def fs_first_menu(self):
        """
        Small menu to determine what file system the user
        wants to know more about. Calls second menu at the
        end.
        """
        count = 1
        print("Offsets")
        print("-" * 10)
        for fs in self.start_offsets:
            print(f"{count}) File system at offset: {fs}")
            count += 1
        print(f"{count})Back")

        self.chosen_offset = int(input("Enter the offset of the file system to view in depth...\n"))
        if self.chosen_offset == count:
            self.main_menu()
        for offset in self.failed_fs:
            if self.chosen_offset == offset:
                prompt = input("This file system can not be decoded automatically, view anyway?")
                if prompt.lower() == "yes":
                    self.manual_menu(self.chosen_offset)
                else:
                    pass
        else:
            self.fs_second_menu()

    def fs_second_menu(self):
        """
        The second small menu to determine what information the user wants
        from the previously decided file system.
        """
        while True:
            print("Options")
            print("-" * 10)
            print("1) Analyse all files")
            print("2) Analyse root")
            print("3) Analyse metadata record")
            print("4) File system hex view")
            print("5) Analyse specific directory")
            print("6) Analyse specific file")
            print("7) Image file EXIF")
            print("8) File hex view")
            print("9) Previous menu")

            prompt = input("Select an option...\n")
            if prompt == "1":
                self.file_analysis(self.chosen_offset)

            elif prompt == "2":
                print("!Currently only analyses root!")
                self.root_analysis(self.chosen_offset)

            elif prompt == "3":
                self.meta_analysis(self.chosen_offset)

            elif prompt == "4":
                self.fs_view(self.chosen_offset)

            elif prompt == "5":
                self.dir_analysis()

            elif prompt == "6":
                file = input("Enter the file to analyse:\n")
                self.specific_file(file)

            elif prompt == "7":
                file = input("Enter the file to analyse:\n")
                self.image_exif(file)

            elif prompt == "8":
                file = input("Enter the files name:\n")
                self.file_view(file)

            elif prompt == "9":
                self.fs_first_menu()
                break


    def main_menu(self):
        print("Select a file to analyse:")
        print("-"*10)
        count = 0
        for file in os.listdir(os.getcwd()):
            if file.endswith(".dd") or file.endswith(".001") or file.endswith(".raw"):
                print(f"{count}) {file}")
                count += 1
            else:
                pass

        self.chosen_file = input("File to analyse:\n")
        self.diskimage = pytsk3.Img_Info(self.chosen_file)
        self.volume_info = pytsk3.Volume_Info(self.diskimage)

        while True:
            print("Options")
            print("_" * 10)
            print("1) General information")
            print("2) View Boot sector")
            print("3) Decode partitions")
            print("4) File system information")
            print("5) Hash verification")
            print("6) Exit")
            prompt = input("")
            if prompt == "1":
                self.general_info()

            elif prompt == "2":
                self.boot_view()

            elif prompt == "3":
                self.partition_table()

            elif prompt == "4":
                if len(self.start_offsets) == 0:
                    print("Please run option 2 first to populate a start offset list...")
                else:
                    self.file_sys_analysis()

            elif prompt == "5":
                if self.chosen_offset is None:
                    print("No file system offsets known currently")
                else:
                    hash_prompt = input("Enter the hash:\n")
                    filename = input("Enter the file to verify:\n")
                    verify = self.hash_compare(filename, hash_prompt)

                    if verify is True:
                        print("Hashes match...")
                        print("")
                    else:
                        print("Hashes do not match")
                        print("")

            elif prompt == "6":
                quit()

            elif prompt == "7":
                test = input("File name:\n")
                self.chosen_offset = 65536
                self.file_view(test)

            else:
                print("Invalid option chosen...")


if __name__ == '__main__':
    c = Decode()
    c.main_menu()
