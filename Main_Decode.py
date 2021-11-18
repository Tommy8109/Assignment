import pytsk3
from datetime import datetime
from Reports import MakeReport
import hashlib


class Decode():
    def __init__(self):
        """Creating the disk image variable which is equivalent to f=open()"""
        self.diskimage = pytsk3.Img_Info("Session2_Image.001")
        self.volume_info = pytsk3.Volume_Info(self.diskimage)
        self.start_offsets = []

        self.report_partition = "Partition Report.csv"
        self.report_fs = "FS Report.csv"
        self.report_files = "Found file report.csv"

        self.chosen_offset = ""
        self.file_pattern = r"(?P<Name>\w+)\.(?P<Extension>\w+)"
        self.img_formats = ["JPEG", "JPG", "PNG", "GIF", "TIFF", "PSD"]
        self.file_list = []
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

        print("File name: DiskImage.001")
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
                report = MakeReport()
                report.file_sys_report(fs_type, fs_info.info.block_count, fs_info.info.block_size,
                                       fs_info.info.endian, fs_info.info.inum_count, fs_info.info.flags)

            except:
                failed_offsets.append(partition_offset)
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
        for file in root_dir:
            if file.info.meta != None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    file_type_str = "Dir"
                else:
                    file_type_str = 'File'

            ascii_name = file.info.name.name.decode("ascii")
            print(ascii_name)
            self.file_list.append(ascii_name)

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

            report = MakeReport()
            report.files_report(file_name.name, file_name.type, file_meta.addr, acc_time, crt_time, mod_time, meta_time,
                                file_meta.gid, file_meta.size, status)

        print(f"Total files analysed: {self.file_count}")
        print(f"Deleted files found: {deleted_count}")
        print("")

    def meta_analysis(self, offset, record):
        partition = pytsk3.FS_Info(self.diskimage, offset)
        partition.open_meta(record)

    def hash_compare(self, file, algorithm, user_hash):
        with open(file, "rb") as f:
            bytes = f.read()

            if str(algorithm).lower() == "sha256":
                readable_hash = hashlib.sha256(bytes).hexdigest()
            else:
                readable_hash = hashlib.md5(bytes).hexdigest()

        if readable_hash == str(user_hash).lower():
            return True

        else:
            return False

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
        else:
            self.fs_second_menu(self.chosen_offset)

    def fs_second_menu(self, offset):
        """
        The second small menu to determine what information the user wants
        from the previously decided file system.
        """
        while True:
            print("Options")
            print("-" * 10)
            print("1) Analyse files")
            print("2) Analyse Directory")
            print("3) Analyse metadata record")
            print("4) Previous menu")

            prompt = input("Select an option...\n")
            if prompt == "1":
                self.file_analysis(self.chosen_offset)

            elif prompt == "2":
                print("!Currently only analyses root!")
                self.root_analysis(self.chosen_offset)

            elif prompt == "3":
                record_num = int(input("Enter the number of the metadata record:\n"))
                self.meta_analysis(offset, record_num)

            elif prompt == "4":
                self.fs_first_menu()
                break

    def main_menu(self):
        while True:
            print("Options")
            print("_" * 10)
            print("1) General information")
            print("2) Decode partitions")
            print("3) File system information")
            print("4) Hash verification")
            print("5) Exit")
            prompt = input("")
            if prompt == "1":
                self.general_info()

            elif prompt == "2":
                self.partition_table()

            elif prompt == "3":
                if len(self.start_offsets) == 0:
                    print("Please run option 2 first to populate a start offset list...")
                else:
                    self.file_sys_analysis()

            elif prompt == "4":
                hash_prompt = input("Enter the hash:\n")
                algorithm = input("Enter the algorithm:\n")
                verify = self.hash_compare("Session2_Image.001", algorithm, hash_prompt)
                if verify is True:
                    print("Hashes match...\n")
                else:
                    print("Hashes do not match...\n")

            elif prompt == "5":
                quit()

            else:
                print("Invalid option chosen...")


if __name__ == '__main__':
    c = Decode()
    c.main_menu()
