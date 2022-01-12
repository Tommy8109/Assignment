"""All of the imports necessary for the programs functionality"""
import sqlite3
import time
import os
from tkinter import *
from tkinter import ttk
from tkinter.ttk import *
from tkinter import messagebox
import tkinter.filedialog as filedialog
from scrollableFrame import ScrollableFrame
import re
from pytskHandler import PytskInfo
from functools import partial
from FileCarver import FileCarving
import exifread
import math


class ForensicGui():
    """
    Class - ForensicGui
    --------------------
    Purpose:    This is the container for all of the programs functionality.
    It contains all of the methods needed to make the program work. The overall
    point of this program is to retrieve information of forensic significance from
    a raw image and present it in a graphical user interface.
    """

    def __init__(self):
        """
        Method - __init__
        -------------------
        Purpose - This is the constructor for the ForensicGui class, it sets up all of the
        instance variables for the program.

        The first block of variables are private variables and they contain the names
        of the files that are used as background images for screens in the UI.

        The second block contains the Tkinter variables, which are needed to make the GUI
        work. It sets up a Tk instance, an app title, screen size and a variable for frames.

        The blocks of variables after are used in various methods and have different data types.
        One of these is StringVar() which is a variable relating to a tkinter entry box.
        """

        self.__InitialScreenFile = "FirstScreen.png"
        self.__MainScreenFile = "MainScreen.png"
        self.__AltMainScreenFile = "AltMainScreen.png"
        self.__PartitionScreen = "PartitionScreen.png"
        self.__FileSysScreen = "FSScreen.png"
        self.__FilesScreen = "FilesScreen.png"
        self.__FileMetaScreen = "AllFileMetaScreen.png"
        self.__SpecFile = "SpecFile.png"
        self.__ChooseFileScreen = "SpecificFile.png"
        self.__EXIFscreen = "EXIFscreen.png"
        self.__FileCarveScreen = "FileCarve.png"
        self.__FileCarveDoneScreen = "FileCarveComplete.png"
        self.__HashingScreen = "GetHash.png"
        self.__PhotoScreenFirst = "PhotoViewerFirst.png"
        self.__PhotoScreenSecond = "PhotoViewerSecond.png"
        self.__FilesScreenType = "FileCarveType.png"
        self.__LoadScreenFile = "LoadScreen.png"
        self.__MD5HashScreen = "MD5Screen.png"
        self.__SHAHashScreen = "SHAScreen.png"
        self.__FileHashScreen = "HashByFileScreen.png"
        self.__SpecificDirScreen = "SpecificDir.png"
        self.__SignatureScreen = "FileSigScreen.png"
        self.__HexScreen = "HexScreen.png"
        self.__RegScreen = "RegistryScreen.png"

        self.__MainWindow = Tk()
        self.__title = "APDF FORENSIC TOOL"
        self.__screen_geometry = "1920x1080"
        self.CurrentFrame = None

        self.IsE01 = bool
        self.db_exists = False
        self.diskimage = object
        self.img_info = object
        self.tsk_handle = object
        self.file_count = int
        self.md5_check = int
        self.sha_check = int
        self.filesize = StringVar()
        self.currentSector = StringVar()
        self.numberOfSectors = 0
        self.currentSelectedSector = 0
        self.BottomFrame = None
        self.part_scheme = ""
        self.OS_name = ""

        self.root_files = []
        self.root_directories = []
        self.ForensicFiles = []
        self.startoffsets = []
        self.fs_sizes = []
        self.failed_fs = []
        self.workingOffsets = []
        self.dir_names = []
        self.file_list = []
        self.RootFiles = []
        self.RootDirs = []
        self.Specific_dir_files = []
        self.Specific_dir_subdir = []
        self.image_exts = ["jpg", "png", "bmp"]
        self.text_exts = ["doc", "docx", "pptx", "txt", "pdf"]
        self.filesystemfiles = ["$AttrDef", "$BadClus", "$Bitmap", "$Boot", "$FAT1", "$FAT2", "$I30", "$LogFile",
                                "$MBR", "$MFT", "$MTFMirr", "$Objld", "$OrphanFiles", "%Quota", "$Reparse", "$Volume",
                                "$Secure", "$UpCase"]

        self.ChosenFile = StringVar()
        self.chosenOffset = StringVar()
        self.FileToDecode = StringVar()
        self.DirToDecode = StringVar()
        self.EXIFfile = StringVar()
        self.FileToCarve = StringVar()
        self.DirToSaveTo = StringVar()
        self.UserHash = StringVar()
        self.HashFile = StringVar()
        self.PhotoToView = StringVar()
        self.file_type = StringVar()
        self.dir_to_analyse = StringVar()
        self.file_to_analyse = StringVar()
        self.file_filter = StringVar()

    def ClearWindow(self):
        window = self.__MainWindow
        _list = window.winfo_children()

        for item in _list:
            item.destroy()

    def CreateFrame(self, ImageFileName):
        """
        Method - CreateFrame
        ---------------------
        Purpose - This is a method to set up a tkinter frame and
        return it as an object.

        :param ImageFileName: The image to use as a background
        :return: Returns a frame objects
        """
        menuScreen = self.__MainWindow

        frame = Frame(menuScreen, width=682, height=453, bg='#001636', )
        frame.pack(side=LEFT)

        background_label = ttk.Label(frame, text="")
        background_label.place(x=0, y=0)

        logo = PhotoImage(file=ImageFileName)
        background_label.config(image=logo)
        background_label.img = logo
        background_label.config(image=background_label.img)
        frame.place(x=26, y=235)
        return frame

    def DestroyFrame(self):
        """
        Method - DestroyFrame
        ----------------------
        Purpose - This is a method to destroy the current
        tkinter frame
        """

        self.CurrentFrame.destroy()

    def format_result(self, sql_result):
        result = str(sql_result)
        result = result.replace("[", "")
        result = result.replace("]", "")
        result = result.replace("'", "")
        result = result.replace("(", "")
        result = result.replace(")", "")
        result = result.replace(",", "")
        result = result.replace("{", "")
        result = result.replace("}", "")

        return result

    def first_screen(self):
        """
        Method - first_screen
        -----------------------
        Purpose - This method builds the first screen displayed when
        the program is run. It gets a list of suitable files using
        the OS import and lists them on the screen. The file chosen
        from that list is stored as a StringVar().
        """
        self.ClearWindow()
        firstScreen = self.__MainWindow
        firstScreen.title(self.__title)
        firstScreen.geometry(self.__screen_geometry)

        firstScreen.attributes("-topmost", False)
        firstScreen.resizable(False, False)
        background = ttk.Label(firstScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__InitialScreenFile, master=firstScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        exts = [".raw", ".dd", ".001", "E01"]
        self.ForensicFiles = []
        for file in os.listdir(os.getcwd()):
            for extension in exts:
                if file.endswith(extension):
                    self.ForensicFiles.append(file)

        ycord = 140

        for file in self.ForensicFiles:
            Label(firstScreen, text=file, background="#D9D9D9", font=("Roboto", 20)).place(x=50, y=ycord)
            ycord += 50

        entryFile = ttk.Entry(firstScreen, textvariable=self.ChosenFile, width=60)
        entryFile.place(x=755, y=458)

        btnContinue = ttk.Button(firstScreen, text=" Analyse ", command=self.LoadingScreen)
        btnContinue.place(x=755, y=510)

        btnDialog = ttk.Button(firstScreen, command=self.FileBrowse, text="Or browse files")
        btnDialog.place(x=755, y=560)

        firstScreen.option_add('*tearOff', False)
        firstScreen.mainloop()

    def FileBrowse(self):
        filetypes = (
            ('001 Files', '*.001'),
            ('E01 Files', '*.E01'),
            ('Raw Files', '*.raw'),
            ('DD files', '*.dd')
        )
        cwd = os.getcwd()
        filename = filedialog.askopenfilename(title="Choose a file", initialdir=cwd, filetypes=filetypes)
        self.ChosenFile.set(filename)

    def LoadingScreen(self):
        self.ClearWindow()
        ProcessScreen = self.__MainWindow
        ProcessScreen.title(self.__title)
        ProcessScreen.geometry(self.__screen_geometry)

        ProcessScreen.attributes("-topmost", False)
        ProcessScreen.resizable(False, False)
        background = ttk.Label(ProcessScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__LoadScreenFile, master=ProcessScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        progress = Progressbar(ProcessScreen, orient=HORIZONTAL, length=200, mode='determinate')
        progress.place(x=700, y=250)

        xcord = 700
        ycord = 375
        bar_value = 20

        LoadText = ["Discovering Partitions", "Discovering File systems", "Analysing root directories",
                    "Analysing file metadata", "Calculating hash values", "Done!"]

        for text in LoadText:
            time.sleep(1)
            Label(ProcessScreen, text=text, background="#D9D9D9", font=("Roboto", 20)).place(x=xcord, y=ycord)
            progress['value'] = bar_value
            bar_value += 20
            ycord += 50
            ProcessScreen.update_idletasks()
            time.sleep(2)

        self.MainScreen()

    def MainScreen(self):
        """
        Method - MainScreen
        --------------------
        Purpose - This method builds the "Hub" screen. It is the main screen
        that contains all of the options of the program. It is also where basic
        image information is listed. This is th screen  that is called to on almost
        all "back" buttons throughout the program.

        There is a check done at the top of the program to determine whether the user
        selected an E01 file. E01 files contain extra case information and have to be
        dealt with differently. It also has a different background image.

        The functions of the program are listed via Tkinter's menubars, seen on lines
        222-259.
        """

        # self.connection = sqlite3.connect("APDF Log\\APDF report.db")
        # self.cursor = self.connection.cursor()

        if self.db_exists is False:
            pattern = r"(?P<name>.+)\.(.{2})"
            regex = re.compile(pattern)
            m = regex.search(self.ChosenFile.get())
            if m is not None:
                extension = m.group(2)
                if extension == "E0":
                    self.IsE01 = True
                    self.tsk_handle = PytskInfo(self.ChosenFile.get(), "E01")
                    self.tsk_handle.main()
                    self.OS_name = self.tsk_handle.product_name
                    self.file_list = self.tsk_handle.files
                    self.dir_names = self.tsk_handle.directories
                    self.RootFiles = self.tsk_handle.root_files
                    self.RootDirs = self.tsk_handle.root_dirs

                else:
                    self.IsE01 = False
                    self.tsk_handle = PytskInfo(self.ChosenFile.get(), extension)
                    self.tsk_handle.main()
                    self.file_list = self.tsk_handle.files
                    self.dir_names = self.tsk_handle.directories
                    self.RootFiles = self.tsk_handle.root_files
                    self.RootDirs = self.tsk_handle.root_dirs

            else:
                self.IsE01 = False

        else:
            pass

        self.ClearWindow()
        MainScreen = self.__MainWindow
        MainScreen.title(self.__title)
        MainScreen.geometry(self.__screen_geometry)

        MainScreen.attributes("-topmost", False)
        MainScreen.resizable(False, False)
        background = ttk.Label(MainScreen, text="")
        background.place(x=0, y=0)

        if self.IsE01 is False:
            logo = PhotoImage(file=self.__MainScreenFile, master=MainScreen)
        else:
            logo = PhotoImage(file=self.__AltMainScreenFile, master=MainScreen)

        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        menubar = Menu(MainScreen)
        MainScreen.config(menu=menubar)

        if self.chosenOffset.get() == "":
            PartitionMenu = Menu(menubar)
            FSMenu = Menu(menubar)
            HexMenu = Menu(menubar)
            QuitMenu = Menu(menubar)

            menubar.add_cascade(menu=PartitionMenu, label='Partitions ')
            menubar.add_cascade(menu=FSMenu, label='File systems')
            menubar.add_cascade(menu=HexMenu, label='Hex viewer')

            PartitionMenu.add_command(label='Decode', command=self.partitions)
            FSMenu.add_command(label='Decode', command=self.file_sys_decode)
            QuitMenu.add_command(label='Quit', command=quit)


        else:
            PartitionMenu = Menu(menubar)
            FSMenu = Menu(menubar)
            HexMenu = Menu(menubar)
            QuitMenu = Menu(menubar)
            FileMenu = Menu(menubar)
            CarveMenu = Menu(menubar)
            HashMenu = Menu(menubar)
            RegMenu = Menu(menubar)


            menubar.add_cascade(menu=PartitionMenu, label='Partitions ')
            menubar.add_cascade(menu=FSMenu, label='File systems')
            menubar.add_cascade(menu=FileMenu, label='In depth')
            menubar.add_cascade(menu=CarveMenu, label='File carving')
            menubar.add_cascade(menu=HashMenu, label='Hashing')
            menubar.add_cascade(menu=HexMenu, label='Hex viewer')
            menubar.add_cascade(menu=RegMenu, label='Registry')

            PartitionMenu.add_command(label='Decode', command=self.partitions)

            FSMenu.add_command(label='Decode', command=self.file_sys_decode)

            FileMenu.add_command(label='Analyse root', command=self.root_analyse)
            FileMenu.add_command(label='All file metadata', command=self.AllFileMeta)
            FileMenu.add_command(label='Specific file', command=self.specific_file)
            FileMenu.add_command(label='Specific directory', command=self.get_specific_dir)
            FileMenu.add_command(label='EXIF data', command=self.GetExifFile)
            FileMenu.add_command(label='File Hex')
            FileMenu.add_command(label='File signature', command=self.file_signatures)
            FileMenu.add_command(label='Photo viewer', command=self.photo_viewer_first)

            CarveMenu.add_command(label='Carve specific', command=self.FileCarver)
            CarveMenu.add_command(label='Carve System', command=self.CarveSys)
            CarveMenu.add_command(label='Carve by type', command=self.CarveByTypeGet)
            CarveMenu.add_command(label='Carve All', command=self.CarveAll)

            HashMenu.add_command(label='Hash compare', command=self.get_hashes)

            HexMenu.add_command(label='Hex view', command=self.boot_view_screen)

            RegMenu.add_command(label='Registry info', command=self.registry_info)

            QuitMenu.add_command(label='Quit', command=quit)

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        if self.IsE01 is False:
            qry_size = """SELECT ByteSize FROM BasicInfo"""
            cursor.execute(qry_size)
            size = cursor.fetchall()

            qry_sectors = """SELECT Sectors From BasicInfo"""
            cursor.execute(qry_sectors)
            sectors = cursor.fetchall()

            qry_alloc = """SELECT Allocated From BasicInfo"""
            cursor.execute(qry_alloc)
            alloc = cursor.fetchall()

            qry_unalloc = """SELECT Unallocated From BasicInfo"""
            cursor.execute(qry_unalloc)
            unall = cursor.fetchall()

            lblName = ttk.Label(MainScreen, text=self.ChosenFile.get(), background="#D9D9D9", font=("Roboto", 20))
            lblName.place(x=60, y=91)
            lblBytes = ttk.Label(MainScreen, text=size, background="#D9D9D9", font=("Roboto", 20))
            lblBytes.place(x=124, y=352)
            lblsectors = ttk.Label(MainScreen, text=sectors, background="#D9D9D9", font=("Roboto", 20))
            lblsectors.place(x=124, y=480)
            lblAll = ttk.Label(MainScreen, text=alloc, background="#D9D9D9", font=("Roboto", 20))
            lblAll.place(x=124, y=658)
            lblUnAll = ttk.Label(MainScreen, text=unall, background="#D9D9D9", font=("Roboto", 20))
            lblUnAll.place(x=124, y=841)

        else:
            qry_size = """SELECT ByteSize FROM BasicInfo"""
            cursor.execute(qry_size)
            size = cursor.fetchall()

            qry_sectors = """SELECT Sectors From BasicInfo"""
            cursor.execute(qry_sectors)
            sectors = cursor.fetchall()

            qry_alloc = """SELECT Allocated From BasicInfo"""
            cursor.execute(qry_alloc)
            alloc = cursor.fetchall()

            qry_unalloc = """SELECT Unallocated From BasicInfo"""
            cursor.execute(qry_unalloc)
            unall = cursor.fetchall()

            qry_casenum = """SELECT CaseNum FROM BasicInfo"""
            cursor.execute(qry_casenum)
            case_num = cursor.fetchall()

            qry_evidnum = """SELECT EvidenceNum FROM BasicInfo"""
            cursor.execute(qry_evidnum)
            evid_num = cursor.fetchall()

            qry_name = """SELECT ExaminerName FROM BasicInfo"""
            cursor.execute(qry_name)
            case_name = cursor.fetchall()
            case_name = self.format_result(case_name)

            qry_hash = """SELECT Hash FROM BasicInfo"""
            cursor.execute(qry_hash)
            case_hash = self.format_result(cursor.fetchall())
            case_hash = str(case_hash).replace("\"", "")
            case_hash = str(case_hash).replace("MD5: ", "")

            lblName = ttk.Label(MainScreen, text=self.ChosenFile.get(), background="#D9D9D9", font=("Roboto", 20))
            lblName.place(x=60, y=91)
            lblBytes = ttk.Label(MainScreen, text=size, background="#D9D9D9", font=("Roboto", 20))
            lblBytes.place(x=124, y=352)
            lblsectors = ttk.Label(MainScreen, text=sectors, background="#D9D9D9", font=("Roboto", 20))
            lblsectors.place(x=124, y=480)
            lblAll = ttk.Label(MainScreen, text=alloc, background="#D9D9D9", font=("Roboto", 20))
            lblAll.place(x=124, y=658)
            lblUnAll = ttk.Label(MainScreen, text=unall, background="#D9D9D9", font=("Roboto", 20))
            lblUnAll.place(x=124, y=841)

            lblCaseNum = ttk.Label(MainScreen, text=case_num, background="#D9D9D9", font=("Roboto", 20))
            lblCaseNum.place(x=550, y=424)
            lblEvNum = ttk.Label(MainScreen, text=evid_num, background="#D9D9D9", font=("Roboto", 20))
            lblEvNum.place(x=1071, y=424)
            lblExaminer = ttk.Label(MainScreen, text=case_name, background="#D9D9D9", font=("Roboto", 20))
            lblExaminer.place(x=550, y=645)
            lblHash = ttk.Label(MainScreen, text=case_hash, background="#D9D9D9", font=("Roboto", 20))
            lblHash.place(x=1091, y=645)

        self.db_exists = True

    def partitions(self):
        """
        Method - partition_decode
        --------------------------
        Purpose - This screen is where the partitions of the image
        are decoded. It uses a database to retrieve the Type, start and length
        of each partition in the table. It will also discover the partitioning
        scheme in use (MBR/GPT). The start offsets discovered here are used in
        the file_sys_decode method.
        """

        self.ClearWindow()
        PartScreen = self.__MainWindow
        PartScreen.title(self.__title)
        PartScreen.geometry(self.__screen_geometry)

        PartScreen.attributes("-topmost", False)
        PartScreen.resizable(False, False)
        background = ttk.Label(PartScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__PartitionScreen, master=PartScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_total_row = """SELECT * FROM Partitions"""
        cursor.execute(qry_total_row)
        result = cursor.fetchall()
        total_rows = len(result)

        scheme_qry = """SELECT Scheme FROM Partitions WHERE Count=1"""
        cursor.execute(scheme_qry)
        scheme = cursor.fetchall()

        lblScheme = ttk.Label(PartScreen, text=scheme, background="#D9D9D9", font=("Roboto", 24))
        lblScheme.place(x=134, y=432)

        self.part_scheme = scheme

        xcord1 = 419
        xcord2 = 1230
        xcord3 = 1580
        ycord1 = 189

        count = 0
        for row in range(total_rows):
            count += 1
            qry_type = f"""SELECT Type FROM Partitions WHERE Count={count}"""
            cursor.execute(qry_type)
            ftype = cursor.fetchall()
            formatType = self.format_result(ftype)
            qry_start = f"""SELECT Start FROM Partitions WHERE Count={count}"""
            cursor.execute(qry_start)
            start = cursor.fetchall()
            qry_Sectors = f"""SELECT Sectors FROM Partitions WHERE Count={count}"""
            cursor.execute(qry_Sectors)
            sectors = cursor.fetchall()

            text1 = f"{count}\t\t{formatType}"

            Label(PartScreen, text=text1, background="#D9D9D9", font=("Roboto", 24)).place(x=xcord1, y=ycord1)
            Label(PartScreen, text=start, background="#D9D9D9", font=("Roboto", 24)).place(x=xcord2, y=ycord1)
            Label(PartScreen, text=sectors, background="#D9D9D9", font=("Roboto", 24)).place(x=xcord3, y=ycord1)
            ycord1 += 50

        lblCount = ttk.Label(PartScreen, text=count, background="#D9D9D9", font=("Roboto", 30))
        lblCount.place(x=134, y=163)

        lblBack = ttk.Button(PartScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=396, y=1024)

        btnHelp = ttk.Button(PartScreen, text=' Whats this? ', command=partial(self.display_msg, "PartScreen"))
        btnHelp.place(x=1777, y=15)

    def file_sys_decode(self):
        self.ClearWindow()
        FSScreen = self.__MainWindow
        FSScreen.title(self.__title)
        FSScreen.geometry(self.__screen_geometry)

        FSScreen.attributes("-topmost", False)
        FSScreen.resizable(False, False)
        background = ttk.Label(FSScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FileSysScreen, master=FSScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_total_row = """SELECT * FROM Partitions"""
        cursor.execute(qry_total_row)
        result = cursor.fetchall()
        total_rows = len(result)

        count = 0
        xcord1 = 419
        xcord2 = 1180
        ycord1 = 189

        for row in range(total_rows):
            count += 1
            qry_type = f"""SELECT Type FROM FileSystems WHERE Count={count}"""
            cursor.execute(qry_type)
            sysType = cursor.fetchall()

            qry_clusters = f"""SELECT Clusters FROM FileSystems WHERE Count={count}"""
            cursor.execute(qry_clusters)
            clusters = cursor.fetchall()

            qry_clusSize = f"""SELECT ClusterSize FROM FileSystems WHERE Count={count}"""
            cursor.execute(qry_clusSize)
            clusterSize = cursor.fetchall()

            qry_meta = f"""SELECT MetaRecords FROM FileSystems WHERE Count={count}"""
            cursor.execute(qry_meta)
            metarecords = cursor.fetchall()

            text1 = f"{self.format_result(sysType)}\t\t{self.format_result(clusters)}"
            text2 = f"{self.format_result(metarecords)}\t\t\t{self.format_result(clusterSize)}"

            Label(FSScreen, text=text1, background="#D9D9D9", font=("Roboto", 24)).place(x=xcord1, y=ycord1)
            Label(FSScreen, text=text2, background="#D9D9D9", font=("Roboto", 24)).place(x=xcord2, y=ycord1)
            ycord1 += 50

        xcoord = 10
        ycoord = 172
        count = 0

        for fs in range(total_rows):
            count += 1
            qry_Offset = f"""SELECT Offset FROM Partitions WHERE Count={count}"""
            cursor.execute(qry_Offset)
            offset = cursor.fetchall()
            count += 1
            text = f"{count}) File system at offset: {self.format_result(offset)}"
            Label(FSScreen, text=text, background="#D9D9D9", font=("Roboto", 16)).place(x=xcoord, y=ycoord)
            ycoord += 50

        lblBack = ttk.Button(FSScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=396, y=1024)

        btnHelp = ttk.Button(FSScreen, text=' Whats this? ', command=partial(self.display_msg, "FSScreen"))
        btnHelp.place(x=1777, y=15)

        entryOffset = ttk.Entry(FSScreen, textvariable=self.chosenOffset)
        entryOffset.place(x=20, y=900)

        btnSet = ttk.Button(FSScreen, text="Set offset", command=self.MainScreen)
        btnSet.place(x=20, y=930)

    def root_analyse(self):
        """
        Method - root_analyse
        ---------------------
        Purpose - This method is used to display the directories and files
        found in the root directory of the chosen file system.
        """

        self.ClearWindow()
        rootScreen = self.__MainWindow
        rootScreen.title(self.__title)
        rootScreen.geometry(self.__screen_geometry)

        rootScreen.attributes("-topmost", False)
        rootScreen.resizable(False, False)
        background = ttk.Label(rootScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FilesScreen, master=rootScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        self.root_directories = []
        self.root_files = []

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_rows = """SELECT * FROM RootDirectory"""
        cursor.execute(qry_rows)
        results = cursor.fetchall()
        row_count = []
        for result in results:
            if result[0] == self.chosenOffset.get():
                row_count.append(result[0])
            else:
                pass

        qry_FileName = f"""SELECT * From RootDirectory WHERE FileSys={self.chosenOffset.get()}"""
        cursor.execute(qry_FileName)
        result = cursor.fetchall()

        for r in result:
            #if r[2] == "Root":
            if r[3] == "File":
                self.root_files.append(r[1])
            elif r[3] == "Directory":
                self.root_directories.append(r[1])

        root = self.__MainWindow
        frame = ScrollableFrame(700, 680, root)
        self.CurrentFrame = frame
        sCanvas = frame.getCanvas()

        rowPos = 90
        colPos = 5
        lineHeight = 25
        colFile = colPos

        textFileName = colFile + 10

        for file in self.root_files:
            sCanvas.create_text(textFileName, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=file)
            rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=341, y=292)

        root = self.__MainWindow
        frame = ScrollableFrame(700, 680, root)
        self.CurrentFrame = frame
        sCanvas = frame.getCanvas()

        rowPos = 90
        colPos = 5
        lineHeight = 25
        colDir = colPos

        textDirName = colDir + 10

        for directory in self.root_directories:
            sCanvas.create_text(textDirName, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=directory)
            rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=1100, y=292)

        btnHelp = ttk.Button(rootScreen, text=' Whats this? ', command=partial(self.display_msg, "rootScreen"))
        btnHelp.place(x=1777, y=15)

        lblChosenText = ttk.Label(rootScreen, text=f"Viewing file system:{self.chosenOffset.get()}",
                                  background="#D9D9D9",font=("Roboto", 20))
        lblChosenText.place(x=6, y=358)
        lblChosenFS = ttk.Label(rootScreen, text=self.chosenOffset.get(), background="#D9D9D9", font=("Roboto", 24))
        lblChosenFS.place(x=125, y=558)

        lblFileCount = ttk.Label(rootScreen, text=len(self.root_files), background="#D9D9D9", font=("Roboto", 26))
        lblDirCount = ttk.Label(rootScreen, text=len(self.root_directories), background="#D9D9D9", font=("Roboto", 26))
        lblFileCount.place(x=504, y=160)
        lblDirCount.place(x=1337, y=160)

        btnBack = ttk.Button(rootScreen, text=' Back ', command=self.MainScreen)
        btnBack.place(x=1777, y=55)

    def AllFileMeta(self):
        """
        Method - AllFileMeta
        ---------------------
        Purpose - This method is used to display all of the metadata from
        the files discovered in root_analysis within a scrollable frame.
        """

        self.ClearWindow()
        AllFileScreen = self.__MainWindow
        AllFileScreen.title(self.__title)
        AllFileScreen.geometry(self.__screen_geometry)

        AllFileScreen.attributes("-topmost", False)
        AllFileScreen.resizable(False, False)
        background = ttk.Label(AllFileScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FileMetaScreen, master=AllFileScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnHelp = ttk.Button(AllFileScreen, text=' Whats this? ', command=partial(self.display_msg, "AllFileScreen"))
        btnHelp.place(x=1777, y=15)

        entryFilter = ttk.Entry(AllFileScreen, textvariable=self.file_filter)
        entryFilter.place(x=1646, y=146)

        btnFilter = ttk.Button(AllFileScreen, text=' Filter ', command=self.filtered_meta)
        btnFilter.place(x=1776, y=146)

        root = self.__MainWindow  # sets up TK instance to pass in

        frame = ScrollableFrame(850, 1850, root)  # calling ScrollableFrame import and passing previous line in
        self.CurrentFrame = frame  # Setting current frame
        sCanvas = frame.getCanvas()  # Calling a Frame method

        rowPos = 90  # setting position variables
        textRowPos = 40
        colPos = 5
        lineHeight = 25

        sCanvas.create_text(colPos, 5, fill="#D9D9D9", font=("Roboto", 18), justify=LEFT, width=682, anchor="nw",
                            text="File Metadata")  # This is what shows up at the very top, a header
        colFileName = colPos
        colFileType = colPos + 300
        colAccTime = colPos + 450
        colCrtTime = colPos + 650
        colModTime = colPos + 850
        colMetaTime = colPos + 1050
        colOwnerGID = colPos + 1250
        colSize = colPos + 1350
        colDelStatus = colPos + 1450
        colParentDir = colPos + 1550
        colMetaNum = colPos + 1750

        textFileName = colFileName + 10
        textFileType = colFileType + 10
        textAccTime = colAccTime + 10
        textCrtTime = colCrtTime + 10
        textModTime = colModTime + 10
        textMetaTime = colMetaTime + 10
        textOwnerGID = colOwnerGID + 10
        textSize = colSize + 10
        textDelStatus = colDelStatus + 10
        textParentDir = colParentDir + 10
        textMetaNum = colMetaNum + 10

        # These are all for the subheadings
        sCanvas.create_text(textFileName, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Name")
        sCanvas.create_text(textFileType, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Type")
        sCanvas.create_text(textMetaNum, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Record num")
        sCanvas.create_text(textAccTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Access time")
        sCanvas.create_text(textCrtTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Created time")
        sCanvas.create_text(textModTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Modified time")
        sCanvas.create_text(textMetaTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw",
                            text="Metadata changed")
        sCanvas.create_text(textOwnerGID, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Owner group")
        sCanvas.create_text(textSize, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Size")
        sCanvas.create_text(textDelStatus, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Deleted?")
        sCanvas.create_text(textParentDir, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Parent dir")

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_meta = """SELECT * FROM RootMeta"""
        cursor.execute(qry_meta)
        results = cursor.fetchall()

        for result in results:
            if str(result[0]) == str(self.chosenOffset.get()):
                if len(str(result[1])) > 51:
                    name = str(result[1])
                    name = name[0:51]

                    sCanvas.create_text(textFileName, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=name)
                    sCanvas.create_text(textFileType, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[2])
                    sCanvas.create_text(textMetaNum, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[3])
                    sCanvas.create_text(textAccTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[4])
                    sCanvas.create_text(textCrtTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[5])
                    sCanvas.create_text(textModTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[6])
                    sCanvas.create_text(textMetaTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[7])
                    sCanvas.create_text(textOwnerGID, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[8])
                    sCanvas.create_text(textSize, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[9])
                    sCanvas.create_text(textDelStatus, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[10])
                    sCanvas.create_text(textParentDir, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[11])
                    rowPos = rowPos + lineHeight

                else:
                    sCanvas.create_text(textFileName, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[1])
                    sCanvas.create_text(textFileType, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[2])
                    sCanvas.create_text(textMetaNum, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[3])
                    sCanvas.create_text(textAccTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[4])
                    sCanvas.create_text(textCrtTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[5])
                    sCanvas.create_text(textModTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[6])
                    sCanvas.create_text(textMetaTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[7])
                    sCanvas.create_text(textOwnerGID, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[8])
                    sCanvas.create_text(textSize, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[9])
                    sCanvas.create_text(textDelStatus, rowPos, fill="#000000", justify=LEFT, anchor="nw",
                                        text=result[10])
                    sCanvas.create_text(textParentDir, rowPos, fill="#000000", justify=LEFT, anchor="nw",
                                        text=result[11])
                    rowPos = rowPos + lineHeight

        lblBack = ttk.Button(AllFileScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=22, y=205)

        lblFileCount = ttk.Label(AllFileScreen, text=len(self.root_files), background="#D9D9D9",
                                 font=("Roboto", 16))
        lblFileCount.place(x=72, y=115)

        # Refreshing and then placing it
        frame.refreshCanvas(sCanvas)
        frame.place(x=10, y=203)

    def filtered_meta(self):
        self.ClearWindow()
        AllFileScreen = self.__MainWindow
        AllFileScreen.title(self.__title)
        AllFileScreen.geometry(self.__screen_geometry)

        AllFileScreen.attributes("-topmost", False)
        AllFileScreen.resizable(False, False)
        background = ttk.Label(AllFileScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FileMetaScreen, master=AllFileScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnHelp = ttk.Button(AllFileScreen, text=' Whats this? ', command=partial(self.display_msg, "AllFileScreen"))
        btnHelp.place(x=1777, y=15)

        root = self.__MainWindow  # sets up TK instance to pass in

        frame = ScrollableFrame(850, 1850, root)  # calling ScrollableFrame import and passing previous line in
        self.CurrentFrame = frame  # Setting current frame
        sCanvas = frame.getCanvas()  # Calling a Frame method

        rowPos = 90  # setting position variables
        textRowPos = 40
        colPos = 5
        lineHeight = 25

        sCanvas.create_text(colPos, 5, fill="#D9D9D9", font=("Roboto", 18), justify=LEFT, width=682, anchor="nw",
                            text="File Metadata")  # This is what shows up at the very top, a header
        colFileName = colPos
        colFileType = colPos + 300
        colAccTime = colPos + 450
        colCrtTime = colPos + 650
        colModTime = colPos + 850
        colMetaTime = colPos + 1050
        colOwnerGID = colPos + 1250
        colSize = colPos + 1350
        colDelStatus = colPos + 1450
        colParentDir = colPos + 1550
        colMetaNum = colPos + 1750

        textFileName = colFileName + 10
        textFileType = colFileType + 10
        textAccTime = colAccTime + 10
        textCrtTime = colCrtTime + 10
        textModTime = colModTime + 10
        textMetaTime = colMetaTime + 10
        textOwnerGID = colOwnerGID + 10
        textSize = colSize + 10
        textDelStatus = colDelStatus + 10
        textParentDir = colParentDir + 10
        textMetaNum = colMetaNum + 10

        # These are all for the subheadings
        sCanvas.create_text(textFileName, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Name")
        sCanvas.create_text(textFileType, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Type")
        sCanvas.create_text(textMetaNum, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Record num")
        sCanvas.create_text(textAccTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Access time")
        sCanvas.create_text(textCrtTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Created time")
        sCanvas.create_text(textModTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Modified time")
        sCanvas.create_text(textMetaTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw",
                            text="Metadata changed")
        sCanvas.create_text(textOwnerGID, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Owner group")
        sCanvas.create_text(textSize, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Size")
        sCanvas.create_text(textDelStatus, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Deleted?")
        sCanvas.create_text(textParentDir, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Parent dir")

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_meta = f"""SELECT * FROM RootMeta WHERE FileType='{self.file_filter.get()}'"""
        cursor.execute(qry_meta)
        results = cursor.fetchall()

        for result in results:
            if str(result[0]) == str(self.chosenOffset.get()):
                if len(str(result[1])) > 51:
                    name = str(result[1])
                    name = name[0:51]

                    sCanvas.create_text(textFileName, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=name)
                    sCanvas.create_text(textFileType, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[2])
                    sCanvas.create_text(textMetaNum, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[3])
                    sCanvas.create_text(textAccTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[4])
                    sCanvas.create_text(textCrtTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[5])
                    sCanvas.create_text(textModTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[6])
                    sCanvas.create_text(textMetaTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[7])
                    sCanvas.create_text(textOwnerGID, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[8])
                    sCanvas.create_text(textSize, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[9])
                    sCanvas.create_text(textDelStatus, rowPos, fill="#000000", justify=LEFT, anchor="nw",
                                        text=result[10])
                    sCanvas.create_text(textParentDir, rowPos, fill="#000000", justify=LEFT, anchor="nw",
                                        text=result[11])
                    rowPos = rowPos + lineHeight

                else:
                    sCanvas.create_text(textFileName, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[1])
                    sCanvas.create_text(textFileType, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[2])
                    sCanvas.create_text(textMetaNum, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[3])
                    sCanvas.create_text(textAccTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[4])
                    sCanvas.create_text(textCrtTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[5])
                    sCanvas.create_text(textModTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[6])
                    sCanvas.create_text(textMetaTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[7])
                    sCanvas.create_text(textOwnerGID, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[8])
                    sCanvas.create_text(textSize, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[9])
                    sCanvas.create_text(textDelStatus, rowPos, fill="#000000", justify=LEFT, anchor="nw",
                                        text=result[10])
                    sCanvas.create_text(textParentDir, rowPos, fill="#000000", justify=LEFT, anchor="nw",
                                        text=result[11])
                    rowPos = rowPos + lineHeight

        lblBack = ttk.Button(AllFileScreen, text=" Back ", command=self.AllFileMeta)
        lblBack.place(x=22, y=205)

        lblFileCount = ttk.Label(AllFileScreen, text=len(self.root_files), background="#D9D9D9",
                                 font=("Roboto", 16))
        lblFileCount.place(x=72, y=115)

        # Refreshing and then placing it
        frame.refreshCanvas(sCanvas)
        frame.place(x=10, y=203)

    def specific_file(self):
        """
        Method - specific_file
        -------------------------
        Purpose - This method does the same as specific_file, but for one,
        user chosen, file. It retrieves the same information and displays
        it in the same way.
        """

        self.ClearWindow()
        GetFileScreen = self.__MainWindow
        GetFileScreen.title(self.__title)
        GetFileScreen.geometry(self.__screen_geometry)

        GetFileScreen.attributes("-topmost", False)
        GetFileScreen.resizable(False, False)
        background = ttk.Label(GetFileScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__ChooseFileScreen, master=GetFileScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        entry_filename = ttk.Entry(GetFileScreen, textvariable=self.file_to_analyse)
        entry_filename.place(x=825, y=305)

        btnAnalyse = ttk.Button(GetFileScreen, text='Analyse', command=self.show_specific_file)
        btnAnalyse.place(x=825, y=375)

        btnBack = ttk.Button(GetFileScreen, text=' back ', command=self.MainScreen)
        btnBack.place(x=88, y=935)

    def show_specific_file(self):
        self.ClearWindow()
        SpecFileMeta = self.__MainWindow
        SpecFileMeta.title(self.__title)
        SpecFileMeta.geometry(self.__screen_geometry)

        SpecFileMeta.attributes("-topmost", False)
        SpecFileMeta.resizable(False, False)
        background = ttk.Label(SpecFileMeta, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FileMetaScreen, master=SpecFileMeta)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_meta = f"""SELECT * FROM RootMeta WHERE Name='{self.file_to_analyse.get()}'"""
        cursor.execute(qry_meta)
        results = cursor.fetchall()

        root = self.__MainWindow

        frame = ScrollableFrame(850, 1850, root)
        self.CurrentFrame = frame
        sCanvas = frame.getCanvas()

        rowPos = 90
        textRowPos = 40
        colPos = 5
        lineHeight = 25

        sCanvas.create_text(colPos, 5, fill="#D9D9D9", font=("Roboto", 18), justify=LEFT, width=682, anchor="nw",
                            text="File Metadata")
        colFileName = colPos
        colFileType = colPos + 300
        colAccTime = colPos + 450
        colCrtTime = colPos + 650
        colModTime = colPos + 850
        colMetaTime = colPos + 1050
        colOwnerGID = colPos + 1250
        colSize = colPos + 1350
        colDelStatus = colPos + 1450
        colParentDir = colPos + 1550
        colMetaNum = colPos + 1750

        textFileName = colFileName + 10
        textFileType = colFileType + 10
        textAccTime = colAccTime + 10
        textCrtTime = colCrtTime + 10
        textModTime = colModTime + 10
        textMetaTime = colMetaTime + 10
        textOwnerGID = colOwnerGID + 10
        textSize = colSize + 10
        textDelStatus = colDelStatus + 10
        textParentDir = colParentDir + 10
        textMetaNum = colMetaNum + 10

        # These are all for the subheadings
        sCanvas.create_text(textFileName, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Name")
        sCanvas.create_text(textFileType, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Type")
        sCanvas.create_text(textMetaNum, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Record num")
        sCanvas.create_text(textAccTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Access time")
        sCanvas.create_text(textCrtTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Created time")
        sCanvas.create_text(textModTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Modified time")
        sCanvas.create_text(textMetaTime, textRowPos, fill="#000000", justify=LEFT, anchor="nw",
                            text="Metadata changed")
        sCanvas.create_text(textOwnerGID, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Owner group")
        sCanvas.create_text(textSize, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Size")
        sCanvas.create_text(textDelStatus, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Deleted?")
        sCanvas.create_text(textParentDir, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Parent dir")

        for result in results:
            if len(str(result[1])) > 51:
                name = str(result[1])
                name = name[0:51]

                sCanvas.create_text(textFileName, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=name)
                sCanvas.create_text(textFileType, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[2])
                sCanvas.create_text(textMetaNum, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[3])
                sCanvas.create_text(textAccTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[4])
                sCanvas.create_text(textCrtTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[5])
                sCanvas.create_text(textModTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[6])
                sCanvas.create_text(textMetaTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[7])
                sCanvas.create_text(textOwnerGID, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[8])
                sCanvas.create_text(textSize, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[9])
                sCanvas.create_text(textDelStatus, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[10])
                sCanvas.create_text(textParentDir, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[11])
                rowPos = rowPos + lineHeight

            else:
                sCanvas.create_text(textFileName, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[1])
                sCanvas.create_text(textFileType, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[2])
                sCanvas.create_text(textMetaNum, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[3])
                sCanvas.create_text(textAccTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[4])
                sCanvas.create_text(textCrtTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[5])
                sCanvas.create_text(textModTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[6])
                sCanvas.create_text(textMetaTime, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[7])
                sCanvas.create_text(textOwnerGID, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[8])
                sCanvas.create_text(textSize, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=result[9])
                sCanvas.create_text(textDelStatus, rowPos, fill="#000000", justify=LEFT, anchor="nw",
                                    text=result[10])
                sCanvas.create_text(textParentDir, rowPos, fill="#000000", justify=LEFT, anchor="nw",
                                    text=result[11])
                rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=10, y=203)

        btnBack = ttk.Button(SpecFileMeta, text=' Back ', command=self.specific_file)
        btnBack.place(x=25, y=25)

    def get_specific_dir(self):
        self.ClearWindow()
        SpecDirScreen = self.__MainWindow
        SpecDirScreen.title(self.__title)
        SpecDirScreen.geometry(self.__screen_geometry)

        SpecDirScreen.attributes("-topmost", False)
        SpecDirScreen.resizable(False, False)
        background = ttk.Label(SpecDirScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__SpecificDirScreen, master=SpecDirScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        entryDirName = ttk.Entry(SpecDirScreen, textvariable=self.dir_to_analyse)
        entryDirName.place(x=604, y=182)

        btnAnalyse = ttk.Button(SpecDirScreen, text='Analyse', command=self.Specific_dir)
        btnAnalyse.place(x=604, y=282)

        btnBack = ttk.Button(SpecDirScreen, text=' Back ', command=self.MainScreen)
        btnBack.place(x=1777, y=55)

    def Specific_dir(self):
        """
        Method - Specific_dir
        ---------------------
        Purpose - This method does the same as root_analysis, but for a user chosen directory.
        It uses pytsk methods to retrieve all of the files and sub directories in the chosen
        directory.
        """

        self.ClearWindow()
        SpecDirScreen = self.__MainWindow
        SpecDirScreen.title(self.__title)
        SpecDirScreen.geometry(self.__screen_geometry)

        SpecDirScreen.attributes("-topmost", False)
        SpecDirScreen.resizable(False, False)
        background = ttk.Label(SpecDirScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FilesScreen, master=SpecDirScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_rows = f"""SELECT * FROM RootMeta WHERE ParentDirectory='/{self.dir_to_analyse.get()}' AND Offset='{self.chosenOffset.get()}'"""
        cursor.execute(qry_rows)
        results = cursor.fetchall()

        root = self.__MainWindow
        frame = ScrollableFrame(700, 680, root)
        self.CurrentFrame = frame
        sCanvas = frame.getCanvas()

        rowPos = 90
        colPos = 5
        lineHeight = 25
        colFile = colPos

        textFileName = colFile + 10

        for r in results:
            sCanvas.create_text(textFileName, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",text=r[1])
            rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=341, y=292)

        btnBack = ttk.Button(SpecDirScreen, text=' Back ', command=self.MainScreen)
        btnBack.place(x=1777, y=55)

    def GetExifFile(self):
        """
        Method - GetxifFile
        --------------------
        Purpose - This is the first of 2 EXIF screens. Photos have EXIF
        tags that contain information about the picture, like where it was taken.
        This first screen asks the user for a file name, to get EXIF tags from.
        """

        self.ClearWindow()
        exifScreen = self.__MainWindow
        exifScreen.title(self.__title)
        exifScreen.geometry(self.__screen_geometry)

        exifScreen.attributes("-topmost", False)
        exifScreen.resizable(False, False)
        background = ttk.Label(exifScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__EXIFscreen, master=exifScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnBack = ttk.Button(exifScreen, text=" Back ", command=self.MainScreen)
        btnBack.place(x=69, y=56)

        entryFile = ttk.Entry(exifScreen, textvariable=self.EXIFfile)
        entryFile.place(x=26, y=270)

        btnDecode = ttk.Button(exifScreen, text=" Decode ", command=self.GetEXIF)
        btnDecode.place(x=26, y=400)

        btnHelp = ttk.Button(exifScreen, text=' Whats this? ', command=partial(self.display_msg, "exifScreen"))
        btnHelp.place(x=26, y=500)

    def file_signatures(self):
        self.ClearWindow()
        SignatureScreen = self.__MainWindow
        SignatureScreen.title(self.__title)
        SignatureScreen.geometry(self.__screen_geometry)

        SignatureScreen.attributes("-topmost", False)
        SignatureScreen.resizable(False, False)
        background = ttk.Label(SignatureScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__SignatureScreen, master=SignatureScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnHelp = ttk.Button(SignatureScreen, text=' Whats this? ', command=partial(self.display_msg, "SignatureScreen"))
        btnHelp.place(x=20, y=20)

        btnBack = ttk.Button(SignatureScreen, text=' Back ', command=self.MainScreen)
        btnBack.place(x=20, y=60)

        root = self.__MainWindow
        frame = ScrollableFrame(700, 1700, root)
        self.CurrentFrame = frame
        sCanvas = frame.getCanvas()

        rowPos = 90
        colPos = 5
        lineHeight = 25
        colFileName = colPos
        colExtension = colPos + 600
        colDescription = colPos + 950
        colMatch = colPos + 1350

        textFileName = colFileName + 10
        textExtension = colExtension + 10
        textDescription = colDescription + 10
        textMatch = colMatch + 10

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_files = f"""SELECT * FROM FileSignatures WHERE FileSys='{self.chosenOffset.get()}'"""
        cursor.execute(qry_files)
        results = cursor.fetchall()

        for r in results:
            name = str(r[1])
            name = name[0:45]
            sCanvas.create_text(textFileName, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=name)
            sCanvas.create_text(textExtension, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=r[2])
            sCanvas.create_text(textDescription, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=r[3])
            sCanvas.create_text(textMatch, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=r[4])

            rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=250, y=140)

    def GetEXIF(self):
        """
        Method - GetEXIF
        -----------------
        Purpose - This is the second EXIF screen, it gets the EXIF tags
        and puts them on the screen.
        It uses the Exif_reader import to get the tags. There are two types
        of EXIF tags chosen for the program, Image and GPS.

        Image tags - These include the make, model and software version of the
        device used to take the picture.

        GPS tags - This includes Latitude and Longitude references and co-ordinates
        """

        self.ClearWindow()
        exifScreen = self.__MainWindow
        exifScreen.title(self.__title)
        exifScreen.geometry(self.__screen_geometry)

        exifScreen.attributes("-topmost", False)
        exifScreen.resizable(False, False)
        background = ttk.Label(exifScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__EXIFscreen, master=exifScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnBack = ttk.Button(exifScreen, text=" Back ", command=self.GetExifFile)
        btnBack.place(x=69, y=56)

        imgtags = []
        gpstags = []

        f = open(self.EXIFfile.get(), "rb")
        tags = exifread.process_file(f)
        for tag in tags.keys():
            if tag in ('Image Make', 'Image Model', 'Image Software'):
                imgtags.append("%s" % (tags[tag]))

        lblMake = ttk.Label(exifScreen, text=imgtags[0], background="#D9D9D9", font=("Roboto", 16))
        lblMake.place(x=491, y=397)
        lblModel = ttk.Label(exifScreen, text=imgtags[1], background="#D9D9D9", font=("Roboto", 16))
        lblModel.place(x=491, y=485)
        lblSoftware = ttk.Label(exifScreen, text=imgtags[2], background="#D9D9D9", font=("Roboto", 16))
        lblSoftware.place(x=645, y=575)

        f = open(self.EXIFfile.get(), "rb")
        tags = exifread.process_file(f)
        for tag in tags.keys():
            if tag in ('GPS GPSLatitudeRef', 'GPS GPSLatitude', 'GPS GPSLongitudeRef', 'GPS GPSLongitude',
                       'GPS GPSAltitudeRef'):
                gpstags.append("%s" % (tags[tag]))

        lblLatRef = ttk.Label(exifScreen, text=gpstags[0], background="#D9D9D9", font=("Roboto", 16))
        lblLatRef.place(x=1458, y=397)
        lblLat = ttk.Label(exifScreen, text=gpstags[1], background="#D9D9D9", font=("Roboto", 16))
        lblLat.place(x=1403, y=485)
        lblLongRef = ttk.Label(exifScreen, text=gpstags[2], background="#D9D9D9", font=("Roboto", 16))
        lblLongRef.place(x=1492, y=575)
        lblLong = ttk.Label(exifScreen, text=gpstags[3], background="#D9D9D9", font=("Roboto", 16))
        lblLong.place(x=1429, y=673)

    def get_hashes(self):
        self.ClearWindow()
        GetHashScreen = self.__MainWindow
        GetHashScreen.title(self.__title)
        GetHashScreen.geometry(self.__screen_geometry)

        GetHashScreen.attributes("-topmost", False)
        GetHashScreen.resizable(False, False)
        background = ttk.Label(GetHashScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__HashingScreen, master=GetHashScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        lblBack = ttk.Button(GetHashScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=396, y=1024)

        entryFilename = ttk.Entry(GetHashScreen, textvariable=self.HashFile)
        entryFilename.place(x=156, y=100)

        btnFile = ttk.Button(GetHashScreen, text='Search by filename', command=self.hash_by_file)
        btnFile.place(x=156, y=140)

        entryHash = ttk.Entry(GetHashScreen, textvariable=self.UserHash)
        entryHash.place(x=156, y=390)

        btnMD5 = ttk.Button(GetHashScreen, text=' Search MD5 ', command=self.md5_hash)
        btnMD5.place(x=156, y=450)

        btnSHA = ttk.Button(GetHashScreen, text=' Search SHA256 ', command=self.sha256_hash)
        btnSHA.place(x=156, y=510)

        btnHelp = ttk.Button(GetHashScreen, text=' Whats this? ', command=partial(self.display_msg, "GetHashScreen"))
        btnHelp.place(x=1777, y=15)

    def hash_by_file(self):
        self.ClearWindow()
        FileHashScreen = self.__MainWindow
        FileHashScreen.title(self.__title)
        FileHashScreen.geometry(self.__screen_geometry)

        FileHashScreen.attributes("-topmost", False)
        FileHashScreen.resizable(False, False)
        background = ttk.Label(FileHashScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FileHashScreen, master=FileHashScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_name = f"""SELECT * FROM FileHashes WHERE FileName='{self.HashFile.get()}'"""
        cursor.execute(qry_name)
        result = cursor.fetchall()

        labelText = f"We found {len(result)} files matching:"
        lblCount = ttk.Label(FileHashScreen, text=labelText, background="#D9D9D9", font=("Roboto", 20))
        lblCount.place(x=697, y=147)

        ycord = 200

        for r in result:
            Label(FileHashScreen, text=f"Directory: {r[2]}", background="#D9D9D9", font=("Roboto", 16)).place(x=314, y=ycord)
            ycord += 25
            Label(FileHashScreen, text=f"MD5: {r[3]}", background="#D9D9D9", font=("Roboto", 16)).place(x=314, y=ycord)
            ycord += 25
            Label(FileHashScreen, text=f"SHA256: {r[4]}", background="#D9D9D9", font=("Roboto", 16)).place(x=314, y=ycord)
            ycord += 50

        lblBack = ttk.Button(FileHashScreen, text=" Back ", command=self.get_hashes)
        lblBack.place(x=32, y=28)

    def md5_hash(self):
        self.ClearWindow()
        MD5CompareScreen = self.__MainWindow
        MD5CompareScreen.title(self.__title)
        MD5CompareScreen.geometry(self.__screen_geometry)

        MD5CompareScreen.attributes("-topmost", False)
        MD5CompareScreen.resizable(False, False)
        background = ttk.Label(MD5CompareScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__MD5HashScreen, master=MD5CompareScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_name = f"""SELECT * FROM FileHashes WHERE FileSys='{self.chosenOffset.get()}' AND MD5='{self.UserHash.get()}'"""
        cursor.execute(qry_name)
        result = cursor.fetchall()

        if len(result) > 0:
            labelText = f"We found {len(result)} files matching:"
            lblCount = ttk.Label(MD5CompareScreen, text=labelText, background="#D9D9D9", font=("Roboto", 20))
            lblCount.place(x=697, y=147)

            ycord = 200

            for r in result:
                Label(MD5CompareScreen, text=f"Name: {r[1]}", background="#D9D9D9", font=("Roboto", 16)).place(x=314,y=ycord)
                ycord += 25
                Label(MD5CompareScreen, text=f"Directory: {r[2]}", background="#D9D9D9", font=("Roboto", 16)).place(x=314,y=ycord)
                ycord += 25
                Label(MD5CompareScreen, text=f"MD5: {r[3]}", background="#D9D9D9", font=("Roboto", 16)).place(x=314, y=ycord)
                ycord += 50

        else:
            Label(MD5CompareScreen, text="No hashes found", background="#D9D9D9", font=("Roboto", 20)).place(x=314,y=200)

        lblBack = ttk.Button(MD5CompareScreen, text=" Back ", command=self.get_hashes)
        lblBack.place(x=32, y=28)

    def sha256_hash(self):
        self.ClearWindow()
        SHACompareScreen = self.__MainWindow
        SHACompareScreen.title(self.__title)
        SHACompareScreen.geometry(self.__screen_geometry)

        SHACompareScreen.attributes("-topmost", False)
        SHACompareScreen.resizable(False, False)
        background = ttk.Label(SHACompareScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__SHAHashScreen, master=SHACompareScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_name = f"""SELECT * FROM FileHashes WHERE FileSys='{self.chosenOffset.get()}' AND SHA256='{self.UserHash.get()}'"""
        cursor.execute(qry_name)
        result = cursor.fetchall()

        if len(result) > 0:
            labelText = f"We found {len(result)} files matching:"
            lblCount = ttk.Label(SHACompareScreen, text=labelText, background="#D9D9D9", font=("Roboto", 20))
            lblCount.place(x=697, y=147)

            ycord = 200

            for r in result:
                Label(SHACompareScreen, text=f"Name: {r[1]}", background="#D9D9D9", font=("Roboto", 16)).place(x=314, y=ycord)
                ycord += 25
                Label(SHACompareScreen, text=f"Directory: {r[2]}", background="#D9D9D9", font=("Roboto", 16)).place(x=314, y=ycord)
                ycord += 25
                Label(SHACompareScreen, text=f"SHA256: {r[4]}", background="#D9D9D9", font=("Roboto", 16)).place(x=314,y=ycord)
                ycord += 50

        else:
            Label(SHACompareScreen, text="No hashes found", background="#D9D9D9", font=("Roboto", 20)).place(x=314,y=200)

        lblBack = ttk.Button(SHACompareScreen, text=" Back ", command=self.get_hashes)
        lblBack.place(x=32, y=28)

    def display_msg(self, screen):
        if screen == "PartScreen":
            messagebox.showinfo("Partitions", "Shows metadata for discovered\npartitions")

        elif screen == "FSScreen":
            messagebox.showinfo("File system", "Shows metadata for discovered\nfile systems")

        elif screen == "rootScreen":
            messagebox.showinfo("Root", "This shows all files found in the\nroot directory")

        elif screen == "AllFileScreen":
            messagebox.showinfo("File meta", "This shows metadata about all the files discovered\n\t-Name : Name of "
                                             "the file\n\t-Type : Unknown\n\t-Access Time : Time the file was last "
                                             "accessed\n\t-Created Time : Time the file was created\n\t-Modified Time "
                                             ": Time the file was modified\n\t-Metadata time : Time the metadata was "
                                             "changed\n\t-Owner group : File owners group ID\n\t-Size : Size of file "
                                             "in bytes\n\t-Deleted : Files deleted status")

        elif screen == "exifScreen":
            messagebox.showinfo("EXIF", "EXIF is a standard that defines information related\n"
                                        "to an image, like GPS data")

        elif screen == "FileCarverScreen":
            messagebox.showinfo("Carving", "File carving is the process of\nRemoving a file from an image file\n"
                                           "onto the host machine")

        elif screen == "GetHashScreen":
            messagebox.showinfo("Hashing", "Hashing is the process of using\n"
                                           "an algorithm to verify the integrity\nof a file")

        elif screen == "SignatureScreen":
            messagebox.showinfo("Signatures", """File signatures or "magic numbers" are bytes\n
             in a file that identify the file. Used to verify an files extension is accurate""")

    def photo_viewer_first(self):
        self.ClearWindow()
        PhotoViewerScreen = self.__MainWindow
        PhotoViewerScreen.title(self.__title)
        PhotoViewerScreen.geometry(self.__screen_geometry)

        PhotoViewerScreen.attributes("-topmost", False)
        PhotoViewerScreen.resizable(False, False)
        background = ttk.Label(PhotoViewerScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__PhotoScreenFirst, master=PhotoViewerScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        entryFilename = ttk.Entry(PhotoViewerScreen, textvariable=self.PhotoToView)
        entryFilename.place(x=86, y=483)

        btnView = ttk.Button(PhotoViewerScreen, text=' View ', command=self.photo_viewer_second)
        btnView.place(x=86, y=520)

    def photo_viewer_second(self):
        self.ClearWindow()
        PhotoViewerScreen = self.__MainWindow
        PhotoViewerScreen.title(self.__title)
        PhotoViewerScreen.geometry(self.__screen_geometry)

        PhotoViewerScreen.attributes("-topmost", False)
        PhotoViewerScreen.resizable(False, False)
        background = ttk.Label(PhotoViewerScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.PhotoToView.get(), master=PhotoViewerScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        menubar = Menu(PhotoViewerScreen)
        PhotoViewerScreen.config(menu=menubar)

        QuitMenu = Menu(menubar)
        menubar.add_cascade(menu=QuitMenu, label='Quit')
        QuitMenu.add_command(label='Go back', command=self.photo_viewer_first)

    def FileCarver(self):
        """
        Method - FileCarver
        -------------------
        Purpose - This method is used to carve a file out of a file system into the host
        computer. This first method asks the user for a file name and a directory to save it
        to.
        """

        self.ClearWindow()
        FileCarveScreen = self.__MainWindow
        FileCarveScreen.title(self.__title)
        FileCarveScreen.geometry(self.__screen_geometry)

        FileCarveScreen.attributes("-topmost", False)
        FileCarveScreen.resizable(False, False)
        background = ttk.Label(FileCarveScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FileCarveScreen, master=FileCarveScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        entryFileName = ttk.Entry(FileCarveScreen, textvariable=self.FileToCarve)
        entryFileName.place(x=810, y=190)

        btnDone = ttk.Button(FileCarveScreen, text=' Carve ', command=self.FileCarverComplete)
        btnDone.place(x=810, y=700)

        btnHelp = ttk.Button(FileCarveScreen, text=' Whats this? ',
                             command=partial(self.display_msg, "FileCarveScreen"))
        btnHelp.place(x=1777, y=15)

        btnBack = ttk.Button(FileCarveScreen, text=" Back ", command=self.MainScreen)
        btnBack.place(x=42, y=317)

    def FileCarverComplete(self):
        Carver = FileCarving(self.ChosenFile.get(), self.chosenOffset.get())
        Carver.carve_specific(self.FileToCarve.get())
        messagebox.showinfo("Carving", f"{self.FileToCarve.get()} has been carved")

    def CarveByTypeGet(self):
        self.ClearWindow()
        CarveTypeScreen = self.__MainWindow
        CarveTypeScreen.title(self.__title)
        CarveTypeScreen.geometry(self.__screen_geometry)

        CarveTypeScreen.attributes("-topmost", False)
        CarveTypeScreen.resizable(False, False)
        background = ttk.Label(CarveTypeScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FilesScreenType, master=CarveTypeScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnBack = ttk.Button(CarveTypeScreen, text=' Back ', command=self.MainScreen)
        btnBack.place(x=85, y=356)

        entryType = ttk.Entry(CarveTypeScreen, textvariable=self.file_type)
        entryType.place(x=894, y=339)

        btnCarve = ttk.Button(CarveTypeScreen, text=' Carve ', command=self.CarveSys)
        btnCarve.place(x=894, y=400)

        btnSystem = ttk.Button(CarveTypeScreen, text=' Carve system files', command=self.CarveTypeComplete)
        btnSystem.place(x=894, y=735)

    def CarveTypeComplete(self):
        Carver = FileCarving(self.ChosenFile.get(), self.chosenOffset.get())
        Carver.carve_type(self.file_type.get())
        messagebox.showinfo("Carving", f"All {self.file_type.get()} files have been carved")

    def CarveAll(self):
        Carver = FileCarving(self.ChosenFile.get(), self.chosenOffset.get())
        Carver.carve_all()
        messagebox.showinfo("Carving", f"All files from {self.chosenOffset.get()}\n have been carved")

    def CarveSys(self):
        Carver = FileCarving(self.ChosenFile.get(), self.chosenOffset.get())
        Carver.carve_system()
        messagebox.showinfo("Carving", "All system files have been carved")

    def boot_view_screen(self):
        self.ClearWindow()
        HexViewScreen = self.__MainWindow
        HexViewScreen.title(self.__title)
        HexViewScreen.geometry(self.__screen_geometry)

        HexViewScreen.attributes("-topmost", False)
        HexViewScreen.resizable(False, False)
        background = ttk.Label(HexViewScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__HexScreen, master=HexViewScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnBack = ttk.Button(HexViewScreen, text='Back',command=self.MainScreen)
        btnBack.place(x=22, y=28)

        btnHex = ttk.Button(HexViewScreen, text='Show hex', command=self.OpenDialog)
        btnHex.place(x=22, y=80)

        lblScheme = ttk.Label(HexViewScreen, text=self.part_scheme, font=("Roboto", 22))
        lblScheme.place(x=748, y=243)

        self.filesize.set("size on disk in bytes")
        lblFilesize = Label(HexViewScreen, textvariable=self.filesize, background="#D9D9D9", wraplength=555, justify="left")
        lblFilesize.config(font=("Roboto", 12))
        lblFilesize.place(x=612, y=913)

        lblCurrentSector = Label(HexViewScreen, textvariable=self.currentSector, background="#D9D9D9", wraplength=555,
                                 justify="left")
        lblCurrentSector.config(font=("Roboto", 12))
        lblCurrentSector.place(x=811, y=455)

        btnNextSector = ttk.Button(HexViewScreen, command=self.nextSector, text=" Next Sector ").place(x=611, y=455)
        btnPrevSector = ttk.Button(HexViewScreen, command=self.prevSector, text=" Prev Sector ").place(x=711, y=455)

    def showChar(self, v):
        if v >= 32 and v <= 126:
            return chr(v)
        else:
            return '*'

    def readSector(self, sectorN):
        with open(self.ChosenFile.get(), "rb") as file:
            try:
                file.seek(sectorN * 512, os.SEEK_SET)
                block = file.read(512)
                return block
            except ValueError:  # Empty offsetSpinbox
                return

    def OpenDialog(self):
        size = os.path.getsize(self.ChosenFile.get())
        sectors = math.ceil(size / 512) - 1
        self.numberOfSectors = sectors
        self.currentSelectedSector = 0
        block = self.readSector(0)

        self.filesize.set(str(size) + " bytes and " + str(sectors) + " sectors")
        self.currentSector.set("Current Sector = 0")

        self.showSector(block)

    def hexViewer(self):
        frame = self.CreateTopFrame("hexviewertop.png")
        self.CurrentFrame = frame

        self.filesize.set("size on disk in bytes")
        btnOpenDialog = ttk.Button(frame, command=self.OpenDialog, text=" Select File ").place(x=31, y=40)
        lblFilesize = Label(frame, textvariable=self.filesize, bg="#000000", fg="white", wraplength=555, justify="left")
        lblFilesize.config(font=("Roboto", 12))
        lblFilesize.place(x=120, y=39)

        lblCurrentSector = Label(frame, textvariable=self.currentSector, bg="#000000", fg="white", wraplength=555,
                                 justify="left")
        lblCurrentSector.config(font=("Roboto", 12))
        lblCurrentSector.place(x=420, y=39)

        btnNextSector = ttk.Button(frame, command=self.nextSector, text=" Next Sector ").place(x=400, y=98)
        btnPrevSector = ttk.Button(frame, command=self.prevSector, text=" Prev Sector ").place(x=495, y=98)

    def nextSector(self):
        tmpSector = self.currentSelectedSector + 1
        if tmpSector < self.numberOfSectors:
            self.currentSelectedSector = tmpSector
            block = self.readSector(tmpSector)
            self.currentSector.set("Current Sector = " + str(tmpSector))
            self.showSector(block)

    def prevSector(self):
        tmpSector = self.currentSelectedSector - 1
        if tmpSector >= 0:
            self.currentSelectedSector = tmpSector
            block = self.readSector(tmpSector)
            self.currentSector.set("Current Sector = " + str(tmpSector))
            self.showSector(block)

    def showSector(self, random_bytes):
        root = self.__MainWindow

        if self.BottomFrame != None:
            self.BottomFrame.destroy()

        frame = ScrollableFrame(353, 682, root)

        self.BottomFrame = frame

        sCanvas = frame.getCanvas()

        rowPos = 10
        colPos = 60
        lineHeight = 25

        for i in range(32):
            # yellow hex val = efba04
            byteOffsetInFile = (i * 16) + (int(self.currentSelectedSector) * 512)
            offset = (i * 16)
            colPos = 60
            theOffset = "{:04X}".format(byteOffsetInFile)
            sCanvas.create_text(5, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=theOffset)
            charLine = ""
            for j in range(16):
                theCharOffset = offset + j

                theCharAsHex = "{:02X}".format(random_bytes[theCharOffset])
                charLine = charLine + self.showChar(random_bytes[theCharOffset])
                sCanvas.create_text(colPos, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=theCharAsHex)
                colPos = colPos + 25

            sCanvas.create_text(500, rowPos, fill="#000000", justify=LEFT, anchor="nw", text=charLine)
            rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=606, y=486)

    def CreateTopFrame(self, ImageFileName):
        """
            ************************************************************************************************
            METHOD: CreateFrame(self,ImageFileName)
            ************************************************************************************************
            This is a public method that is called when a new screen is made to set up the Tkinter frame
            for it, the background image for it is passed in as a parameter
                - parameters
                    ImageFileName

                - return
                    none

                - return type
                    none

            **************************************************************************************************
            """
        menuScreen = self.__MainWindow

        frame = Frame(menuScreen, width=688, height=136, bg='#001636', )
        frame.pack(side=LEFT)

        background_label = ttk.Label(frame, borderwidth=0, text="")
        background_label.place(x=0, y=0)

        logo = PhotoImage(file=ImageFileName)  # load the image from the file
        background_label.config(image=logo)
        background_label.img = logo
        background_label.config(image=background_label.img)
        frame.place(x=26, y=200)
        return frame

    def registry_info(self):
        self.ClearWindow()
        RegScreen = self.__MainWindow
        RegScreen.title(self.__title)
        RegScreen.geometry(self.__screen_geometry)

        RegScreen.attributes("-topmost", False)
        RegScreen.resizable(False, False)
        background = ttk.Label(RegScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__RegScreen, master=RegScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnBack = ttk.Button(RegScreen, text='Back', command=self.MainScreen)
        btnBack.place(x=25, y=28)

        lblOS = ttk.Label(RegScreen, text=self.OS_name, background="#D9D9D9", font=("Roboto", 20))
        lblOS.place(x=813, y=215)

        root = self.__MainWindow
        frame = ScrollableFrame(700, 1500, root)
        self.CurrentFrame = frame
        sCanvas = frame.getCanvas()

        rowPos = 90
        colPos = 5
        lineHeight = 25
        textRowPos = 40

        colUser = colPos
        colName = colPos + 200
        colURL = colPos + 600

        textUser = colUser + 10
        textName = colName + 10
        textURL = colURL + 10

        sCanvas.create_text(textUser, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="User")
        sCanvas.create_text(textName, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="Name")
        sCanvas.create_text(textURL, textRowPos, fill="#000000", justify=LEFT, anchor="nw", text="URL")

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()
        query = """SELECT * FROM TypedURLS"""
        cursor.execute(query)
        results = cursor.fetchall()

        for r in results:
            sCanvas.create_text(textUser, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=r[0])
            sCanvas.create_text(textName, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=r[1])
            sCanvas.create_text(textURL, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=r[2])

            rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=250, y=265)


"""This is where the program is ran from, it instantiates the class"""
if __name__ == '__main__':
    c = ForensicGui()
    c.first_screen()
