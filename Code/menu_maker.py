import os

class Menus():
    def __init__(self):
        self.line = ("-"*20)

    def type_main(self):
        print("Main menu")
        print(self.line)
        print("1) General information")
        print("2) View Boot sector")
        print("3) Decode partitions")
        print("4) File system information")
        print("5) Hash verification")
        print("6) Exit")
        print(self.line)

    def type_file_sys(self):
        print("File system menu")
        print(self.line)
        print("1) Analyse all files")
        print("2) Analyse root")
        print("3) Analyse metadata record")
        print("4) File system hex view")
        print("5) Analyse specific directory")
        print("6) Analyse specific file")
        print("7) Image file EXIF")
        print("8) File hex view")
        print("9) File signature check")
        print("10) Previous menu")
        print(self.line)

    def type_custom(self, rows, info, name):
        print(name)
        print(self.line)
        count = 1
        for i in range(rows):
            print(f"{count}){info[count - 1]}")
            count += 1
        print(self.line)

    def type_files(self, path, extensions):
        print("Files found")
        print(self.line)
        count = 1
        for file in os.listdir(path):
            for extension in extensions:
                if file.endswith(extension):
                    print(f"{count}) {file}")
                    count += 1
                else:
                    pass
