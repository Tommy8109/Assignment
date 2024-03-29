import pytsk3
from datetime import datetime
from Reports import MakeReport
from Exif_reader import ExifTags
from SigAnalyse import Analyse
from menu_maker import Menus
import hashlib
import os

class ForensicTool():
    """
    Class - ForensicTool
    --------------------
    Purpose - This is the main class that holds all the operations of the program
    It is instantiated at the very bottom of the program
    """
    def __init__(self):
        """
        Constructor
        -----------
        Purpose - The purpose of a constructor is to set up the instance variables for use
        later on in the program, it takes no arguments and has no returns
        """

        self.diskimage = object
        self.volume_info = object
        self.start_offsets = []
        self.fs_sizes = []
        self.failed_fs = []
        self.chosen_file = ""

        self.chosen_offset = ""
        self.file_pattern = r"(?P<Name>\w+)\.(?P<Extension>\w+)"
        self.img_formats = ["JPEG", "JPG", "PNG", "GIF", "TIFF", "PSD"]
        self.file_list = []
        self.meta_records = []
        self.dir_names = []
        self.file_count = int

    def general_info(self):
        """
        Method - general_info
        ------------------------
        Purpose - This function will get the general information about the selected
        image, this includes the file size, allocated space, unallocated space and sector count
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
        Method - partition_table
        --------------------------
        Purpose - Uses the self.volume_info variable to retrieve information about
        each partition and outputs it to the terminal as well as a CSV file
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
        """
        Method - image_exif
        ----------------------
        Purpose - This small function calls to the imported Exif_reader program
        to get the EXIF tags of an image its passed in

        :param file: The file to analyse
        :return: None
        """
        print(f"{file} Image information:")
        exif = ExifTags()
        exif.read_image_tags(file)
        exif.read_gps_tags(file)
        for tag in exif.img_info:
            print(tag)

        for tag in exif.gps_info:
            print(tag)

        print("")

    def file_sys_analysis(self):
        """
        Method - file_sys_analysis
        --------------------------
        Purpose - Analyses the file systems found in the
        partitions. Prints out the file system type, cluster count,
        cluster size, Endianess, metadata records, flags and root inum
        Writes the above information to a CSV file for later viewing.
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

    def root_analysis(self):
        """
        Method - root_analysis
        -----------------------
        Purpose - This function will analyse the root directory of the
        chosen file system. It is able to distinguish between file and
        directory and at the end, prints these out in a readable format
        """

        fs_info = pytsk3.FS_Info(self.diskimage, self.chosen_offset)
        root_dir = fs_info.open_dir(inode=fs_info.info.root_inum)
        dir_count = 0
        file_count = 0
        file_in_dir = 0
        for file in root_dir:
            if file.info.meta != None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    dir_count += 1
                    file_in_dir += 1
                    ascii_name = file.info.name.name.decode("ascii")
                    self.dir_names.append(ascii_name)
                else:
                    file_count += 1
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

    def file_analysis(self):
        """
        Method - file_analysis
        ------------------------
        Purpose - This functions purpose is to analyse all files
        within the root directory, in more detail. It gets a range
        of information out of a file, including its creation time and
        file type.
        """
        partition = pytsk3.FS_Info(self.diskimage, self.chosen_offset)
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

    def meta_analysis(self):
        """
        Not currently in use
        """
        partition = pytsk3.FS_Info(self.diskimage, self.chosen_offset)
        for record in self.meta_records:
            print(record)

    def dir_analysis(self):
        """
        Method - dir_analysis
        ----------------------
        Purpose - This function is similar to the root_analysis method
        but this time for a specific directory, chosen by the user. It outputs
        the same data as root_analysis
        """

        count = 0
        for dir in self.dir_names:
            print(f"{count}) {dir}")
            count += 1

        select_dir = input("Select the directory to view:")
        directory = "/" + select_dir
        try:
            fs_info = pytsk3.FS_Info(self.diskimage, self.chosen_offset)
            directory = fs_info.open_dir(directory)
        except:
            print(f"Could not open directory {directory}")
            self.fs_second_menu()

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

        print(f"Sub directories: {dir_count}   Files in directories {file_in_dir}    Root files: {file_count}")
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

        prompt = input("Restart with newly discovered directories?")
        if prompt.lower() == "yes":
            self.dir_analysis()
        else:
            pass

    def file_sig(self):
        """
        Method - file_sig
        ------------------
        Purpose -This methods purpose is to instansiate the
        imported file sig program and use it to determine
        if the files signature matches
        """

        fname = input("Enter the file to analyse:\n")
        analyse = Analyse(fname,self.chosen_file, self.chosen_offset)
        if analyse.sig_find() is True:
            print("file signature match")
        else:
            print("File signatures don't match")

        self.fs_second_menu()

    def hash_compare(self, filename, user_hash):
        """
        Method - hash_compare
        ----------------------
        Purpose - This funtions purpose is to verify the files hash,
        to make sure it hasn't been changed. It will read the file
        in chunks as its safer.

        :param filename: The name of the file to verify
        :param user_hash: The Hash to compare against
        :return: Returns True or False depending on if hash matches
        """

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
        """
        Method - specific_file
        -----------------------
        Purpose - The purpose of this function is essentially the same as
        the file_analysis method but with only 1 file. This will take a filename
        as an argument and print out its metadata

        :param filename:
        """

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

        fname = filename.replace("/Magic_Folder/", "")
        direct = filename.replace(fname,"")

        analyse = Analyse(fname, self.chosen_file, self.chosen_offset)
        analyse.spec_dir(direct)

        print("")

    def boot_view(self):
        """
        Method - boot_view
        -------------------
        Purpose - This method will print out a hex editor style view
        of the images boot sector.
        """

        print("")
        f = open(self.chosen_file, "rb")
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
        """
        Method - fs_view
        -------------------
        Purpose - This method will print out a hex editor style view
        of the file systems boot sector.
        """

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
        """
        Method - boot_view
        -------------------
        Purpose - This method will print out a hex editor style view
        of a chosen file

        :param filename: This is the file that will be viewed
        """

        partition = pytsk3.FS_Info(self.diskimage, self.chosen_offset)
        file_obj = partition.open(filename)
        file_meta = file_obj.info.meta
        file_size = file_meta.size
        chunk_size = 1024
        offset = 0

        print("")

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
        """
        Method - manual_menu
        -------------------
        Purpose - This method will print out a hex editor style view
        of the file systems boot sector. Used when pytsk3 can't decode
        automatically incase the user wants to manually verify
        """

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
        self.fs_first_menu()

    def fs_first_menu(self):
        """
        Method - fs_first_menu
        -----------------------
        Purpose - Small menu to determine what file system the user
        wants to know more about. Calls second menu at the end. Prints
        out all known file system offsets to make the menu more user friendly
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
                    self.fs_first_menu()
        else:
            self.fs_second_menu()

    def fs_second_menu(self):
        """
        Method - fs_second_menu
        ------------------------
        Purpose: The second small menu to determine what information the user
        wants from the previously decided file system. It will display all the programs
        functions via the MenuMaker
        """

        while True:
            menu = Menus()
            menu.type_file_sys()

            prompt = input("Select an option...\n")
            if prompt == "1":
                if len(self.file_list) is not None:
                    self.file_analysis()
                else:
                    print("Run option 2 first to populate known files...\n")

            elif prompt == "2":
                self.root_analysis()

            elif prompt == "3":
                self.meta_analysis()

            elif prompt == "4":
                self.fs_view(self.chosen_offset)

            elif prompt == "5":
                self.dir_analysis()

            elif prompt == "6":
                if len(self.file_list) is not None:
                    file = input("Enter the file to analyse:\n")
                    self.specific_file(file)
                else:
                    print("Run option 2 first to populate known files...\n")

            elif prompt == "7":
                file = input("Enter the file to analyse:\n")
                self.image_exif(file)

            elif prompt == "8":
                file = input("Enter the files name:\n")
                self.file_view(file)

            elif prompt == "9":
                self.file_sig()

            elif prompt == "10":
                self.fs_first_menu()
                break

    def main_menu(self):
        """
        Method - main_menu
        -------------------
        Purpose - This is the main menu of the program, it is the first
        thing printed to the screen when the program is executed. The options
        are printed via MenuMaker. The very first thing printed to the screen is
        a list of files found in the current directory using OS, this was done to
        increase the overall user friendliness
        """

        menu = Menus()
        exts = [".raw", ".dd", ".001"]
        menu.type_files(os.getcwd(), exts)

        while True:
            self.chosen_file = input("File to analyse:\n")
            try:
                self.diskimage = pytsk3.Img_Info(self.chosen_file)
                self.volume_info = pytsk3.Volume_Info(self.diskimage)
                break
            except:
                print(f"Failed to open {self.chosen_file}, image does not exist")
                print("")

        while True:
            menu.type_main()
            prompt = input("Enter a number\n")
            if prompt == "1":
                self.general_info()

            elif prompt == "2":
                self.boot_view()

            elif prompt == "3":
                self.partition_table()

            elif prompt == "4":
                if len(self.start_offsets) == 0:
                    print("Please run option 3 first to populate a start offset list...")
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

            else:
                print("Invalid option chosen...")


"""This is where the program is ran from. It instantiates the ForensicTool class"""
if __name__ == '__main__':
    c = ForensicTool()
    c.main_menu()
