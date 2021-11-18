import pytsk3
import re
from Reports import MakeReport
from Exif_reader import ExifTags
from Hash_verify import HashVerify


class Decode():
    def __init__(self):
        """Creating the disk image variable which is equivalent to f=open()"""
        self.diskimage = pytsk3.Img_Info("DiskImage.001")
        self.volume_info = pytsk3.Volume_Info(self.diskimage)
        self.start_offsets = []
        self.report_partition = "Partition Report.csv"
        self.report_fs = "FS Report.csv"
        self.chosen_offset = ""
        self.file_pattern = r"(?P<Name>\w+)\.(?P<Extension>\w+)"
        self.img_formats = ["JPEG", "JPG", "PNG", "GIF", "TIFF", "PSD"]

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

    def dir_analysis(self, offset, dirname):
        partition = pytsk3.FS_Info(self.diskimage, offset)
        for file in dirname:
            try:
                file_obj = partition.open(file)
                file_meta = file_obj.info.meta
                file_name = file_obj.info.name

                print(f"Name: {file_name.name}")
                print(f"File type: {file_name.type}")
                print(f"Metadata record number: {file_meta.addr}")
                print(f"Last access time: {file_meta.atime}")
                print(f"Creation time: {file_meta.crtime}")
                print(f"Last modified time: {file_meta.mtime}")
                print(f"Metadata change time: {file_meta.ctime}")
                print(f"Owner group ID: {file_meta.gid}")
                print(f"Size in bytes: {file_meta.size}")

            except:
                print("No files found")

    def file_analysis(self, offset, filename):
        regex = re.compile(self.file_pattern)
        m = regex.search(filename)
        if m is not None:
            extension = m.group(2)
            for ext in self.img_formats:
                if extension.lower() == ext.lower():
                    image_file = True
                else:
                    image_file = False

        else:
            image_file = False

        if image_file is False:
            try:
                partition = pytsk3.FS_Info(self.diskimage, offset)
                file_obj = partition.open(filename)
                file_meta = file_obj.info.meta
                file_name = file_obj.info.name

                print(f"Name: {file_name.name}")
                print(f"File type: {file_name.type}")
                print(f"Metadata record number: {file_meta.addr}")
                print(f"Last access time: {file_meta.atime}")
                print(f"Creation time: {file_meta.crtime}")
                print(f"Last modified time: {file_meta.mtime}")
                print(f"Metadata change time: {file_meta.ctime}")
                print(f"Owner group ID: {file_meta.gid}")
                print(f"Size in bytes: {file_meta.size}")
                if file_meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                    print("Deleted status: Deleted")
                else:
                    print("Deleted status: Not deleted")

            except:
                print("File not found...")
                self.fs_second_menu(self.chosen_offset)

        else:
            partition = pytsk3.FS_Info(self.diskimage, offset)
            file_obj = partition.open(filename)
            file_meta = file_obj.info.meta
            file_name = file_obj.info.name

            print(f"Name: {file_name.name}")
            print(f"File type: {file_name.type}")
            print(f"Metadata record number: {file_meta.addr}")
            print(f"Last access time: {file_meta.atime}")
            print(f"Creation time: {file_meta.crtime}")
            print(f"Last modified time: {file_meta.mtime}")
            print(f"Metadata change time: {file_meta.ctime}")
            print(f"Owner group ID: {file_meta.gid}")
            print(f"Size in bytes: {file_meta.size}")
            print("")
            print("EXIF information...")
            exif = ExifTags()
            print(exif.read_gps_tags(filename))
            print("")
            print(exif.read_image_tags(filename))

    def meta_analysis(self, offset, record):
        partition = pytsk3.FS_Info(self.diskimage, offset)
        partition.open_meta(record)

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

        self.chosen_offset = input("Enter the number of the file system to view in depth...\n")
        self.fs_second_menu(self.chosen_offset)

    def fs_second_menu(self, offset):
        """
        The second small menu to determine what information the user wants
        from the previously decided file system.
        """
        while True:
            print("Options")
            print("-" * 10)
            print("1) Analyse individual file")
            print("2) Analyse Directory")
            print("3) Analyse metadata record")
            print("4) Previous menu")

            prompt = input("Select an option...\n")
            if prompt == "1":
                filename = input("Enter the name of the specific file:\n")
                self.file_analysis(filename, offset)

            elif prompt == "2":
                self.dir_analysis(offset)

            elif prompt == "3":
                record_num = input("Enter the number of the metadata record:\n")
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
            print("4) Exit")
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
                quit()

            else:
                print("Invalid option chosen...")


if __name__ == '__main__':
    c = Decode()
    c.main_menu()
