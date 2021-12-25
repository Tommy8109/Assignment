import pytsk3
import pyewf
from Registry import Registry
from E01_Handler import E01Handler
import re


class RegGet():
    def __init__(self, file, offset):
        self.path_file = "paths.txt"
        self.e01Helper = object
        self.file = file
        self.offset = offset
        self.filesys = object
        self.RegObj = object

    def e01(self):
        e01_glob = pyewf.glob(self.file)
        e01_handle = pyewf.handle()
        e01_handle.open(e01_glob)
        self.e01Helper = E01Handler(e01_handle)

    def registry_info(self):

        self.filesys = pytsk3.FS_Info(self.e01Helper, self.offset)
        regfile = self.filesys.open('/Windows/system32/config/software')
        regbytes = regfile.read_random(0, regfile.info.meta.size)

        with open('SOFTWARE', 'wb') as f:
            f.write(regbytes)

        self.RegObj = Registry.Registry('SOFTWARE')
        key = self.RegObj.open('Microsoft\\Windows NT\\CurrentVersion')
        name = key["ProductName"]

        return name.value()

    def GetUserProfiles(self):
        software_reg = Registry.Registry('E:\\Partition_1\\SOFTWARE')

        key = software_reg.open('Microsoft\\Windows NT\\CurrentVersion\\ProfileList')

        v = key['ProfilesDirectory']

        regex = re.compile('%SystemDrive%\\\\(.+)')
        match = regex.search(v.value())

        if match is not None:

            profiles_directory_name = match.group(1)

            profiles_directory = self.filesys.open_dir(f'/{profiles_directory_name}')

            for file_dir in profiles_directory:
                if file_dir.info.name.name.decode('ascii') == '.' or file_dir.info.name.name.decode('ascii') == '..':
                    continue

                if file_dir.info.meta is not None and file_dir.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    print(
                        f"User profile directory {profiles_directory_name}\\{file_dir.info.name.name.decode('ascii')}")

                    print(
                        f'User profile file {profiles_directory_name}\\{file_dir.info.name.name.decode("ascii")}\\NTUSER.DAT')
