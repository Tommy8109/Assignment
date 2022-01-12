import pytsk3
from Registry import Registry
import re
import pyewf
from E01_Handler import E01Handler

class RegGet():
    def __init__(self, filename, ftype, offset):
        self.filename = filename
        self.user_directories = []
        self.ntuser_paths = []
        self.path = r"/Documents and Settings"
        if ftype == "E01":
            glob_files = pyewf.glob(filename)
            ewf_handle = pyewf.handle()
            ewf_handle.open(glob_files)
            helper = E01Handler(ewf_handle)
            self.filesystem = pytsk3.FS_Info(helper, offset)

        else:
            diskimage = pytsk3.Img_Info(filename)
            self.filesystem = pytsk3.FS_Info(diskimage)

    def write_registry(self):
        try:
            software_file = self.filesystem.open('/Windows/system32/config/software')
            software_bytes = software_file.read_random(0, software_file.info.meta.size)
            f = open('SOFTWARE', 'wb')
            f.write(software_bytes)
            f.close()
        except:
            pass

    def get_product_name(self):

        try:
            software_reg = Registry.Registry('SOFTWARE')
        except FileNotFoundError:
            self.write_registry()

        key_path = software_reg.open('Microsoft\\Windows NT\\CurrentVersion')
        product_name = key_path['ProductName']
        return product_name.value()

    def user_paths(self):
        default_dirs = ["Administrator", "All Users", "Default User", "LocalService", "NetworkService", ".", ".."]
        root_dir = self.filesystem.open_dir(self.path)
        for file in root_dir:
            if file.info.meta != None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    ascii_name = file.info.name.name.decode("ascii")
                    if ascii_name not in default_dirs:
                        self.user_directories.append(ascii_name)

                else:
                    pass

    def ntuser_files(self):
        for user_dir in self.user_directories:
            user_dat_path = self.path + "/" + str(user_dir) + "/NTUSER.DAT"
            print(user_dat_path)
            ntuser_file = self.filesystem.open(user_dat_path)
            ntuser_bytes = ntuser_file.read_random(0, ntuser_file.info.meta.size)
            f = open("NTUSER.DAT", "wb")
            f.write(ntuser_bytes)
            f.close()

            ntuser_reg = Registry.Registry('NTUSER.DAT')
            url_key = ntuser_reg.open('Software\\Microsoft\\INTERNET Explorer\\TypedURLs')
            for val in url_key.values():
                print(val.name())
                print(val.value())


c = RegGet("WindowsOS (1).E01", "E01", 63 * 512)
c.write_registry()
print(c.get_product_name())
c.user_paths()
c.ntuser_files()
c.ntuser_files()
