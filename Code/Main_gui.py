"""All of the imports necessary for the programs functionality"""
import sqlite3
import time
import pytsk3
from datetime import datetime
from Exif_reader import ExifTags
from SigAnalyse import Analyse
from Hash_verify import HashVerify
import os
from tkinter import *
from tkinter import ttk
from tkinter.ttk import *
from tkinter import messagebox
from scrollableFrame import ScrollableFrame
import re
from E01_Handler import E01Handler
from pytskHandler import PytskInfo
from functools import partial
from Extensions import GetExt


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
        self.__EXIFscreen = "EXIFscreen.png"
        self.__FileCarveScreen = "FileCarve.png"
        self.__FileCarveDoneScreen = "FileCarveComplete.png"
        self.__HashingScreen = "GetHash.png"
        self.__PhotoScreenFirst = "PhotoViewerFirst.png"
        self.__PhotoScreenSecond = "PhotoViewerSecond.png"
        self.__FilesScreenType = "FileCarveType.png"
        self.__LoadScreenFile = "LoadScreen.png"

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

    def ClearWindow(self):
        """
        Method - ClearWindow
        ---------------------
        Purpose - The purpose of this method is to remove all things from the
        screen its called on. Its used when moving between screens so that the
        new one can be loaded.
        """

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

        firstScreen.option_add('*tearOff', False)
        firstScreen.mainloop()

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
            pattern = r"(?P<name>.+)\.(.{2})"
            regex = re.compile(pattern)
            m = regex.search(self.ChosenFile.get())
            if m is not None:
                extension = m.group(2)
                if extension == "E0":
                    self.IsE01 = True
                else:
                    self.IsE01 = False
            else:
                self.IsE01 = False

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

        PartitionMenu = Menu(menubar)
        FSMenu = Menu(menubar)
        FileMenu = Menu(menubar)
        CarveMenu = Menu(menubar)
        HashMenu = Menu(menubar)
        newfileMenu = Menu(menubar)
        QuitMenu = Menu(menubar)

        menubar.add_cascade(menu=PartitionMenu, label='Partitions ')
        menubar.add_cascade(menu=FSMenu, label='File systems')
        menubar.add_cascade(menu=FileMenu, label='In depth')
        menubar.add_cascade(menu=CarveMenu, label='File carving')
        menubar.add_cascade(menu=HashMenu, label='Hashing')
        menubar.add_cascade(menu=newfileMenu, label='New file')
        menubar.add_cascade(menu=QuitMenu, label='Quit')

        PartitionMenu.add_command(label='Decode', command=self.partitions)
        PartitionMenu.add_command(label='Boot view')

        FSMenu.add_command(label='Decode', command=self.file_sys_decode)
        FSMenu.add_command(label='Boot view')

        FileMenu.add_command(label='Analyse root', command=self.root_analyse)
        FileMenu.add_command(label='All file metadata', command=self.AllFileMeta)
        FileMenu.add_command(label='Specific file', command=self.specific_file)
        FileMenu.add_command(label='Specific directory', command=self.Get_Specific_dir)
        FileMenu.add_command(label='EXIF data', command=self.GetExifFile)
        FileMenu.add_command(label='File Hex')
        FileMenu.add_command(label='File signature')
        FileMenu.add_command(label='Photo viewer', command=self.photo_viewer_first)

        CarveMenu.add_command(label='Carve specific', command=self.FileCarver)
        CarveMenu.add_command(label='Carve by type', command=self.CarveByTypeGet)
        CarveMenu.add_command(label='Carve All', command=self.CarveAll)

        HashMenu.add_command(label='Hash compare', command=self.get_hashes)

        newfileMenu.add_command(label='Analyse different file', command=self.first_screen)

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
            lblMb = ttk.Label(MainScreen, text=sectors, background="#D9D9D9", font=("Roboto", 20))
            lblMb.place(x=124, y=480)
            lblSec = ttk.Label(MainScreen, text=alloc, background="#D9D9D9", font=("Roboto", 20))
            lblSec.place(x=124, y=595)
            lblAll = ttk.Label(MainScreen, text=unall, background="#D9D9D9", font=("Roboto", 20))
            lblAll.place(x=124, y=735)

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

            qry_hash = """SELECT Hash FROM BasicInfo"""
            cursor.execute(qry_hash)
            case_hash = self.format_result(cursor.fetchall())

            lblName = ttk.Label(MainScreen, text=self.ChosenFile.get(), background="#D9D9D9", font=("Roboto", 20))
            lblName.place(x=60, y=91)
            lblBytes = ttk.Label(MainScreen, text=size, background="#D9D9D9", font=("Roboto", 20))
            lblBytes.place(x=124, y=352)
            lblMb = ttk.Label(MainScreen, text=sectors, background="#D9D9D9", font=("Roboto", 20))
            lblMb.place(x=124, y=480)
            lblSec = ttk.Label(MainScreen, text=alloc, background="#D9D9D9", font=("Roboto", 20))
            lblSec.place(x=124, y=595)
            lblAll = ttk.Label(MainScreen, text=unall, background="#D9D9D9", font=("Roboto", 20))
            lblAll.place(x=124, y=735)

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
            if r[2] == "Root":
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

        ycord = 292
        for dir in self.root_directories:
            Label(rootScreen, text=dir, background="#D9D9D9", font=("Roboto", 16)).place(x=1325, y=ycord)
            ycord += 50

        btnHelp = ttk.Button(rootScreen, text=' Whats this? ', command=partial(self.display_msg, "rootScreen"))
        btnHelp.place(x=1777, y=15)

        lblChosenFS = ttk.Label(rootScreen, text=self.chosenOffset.get(), background="#D9D9D9", font=("Roboto", 24))
        lblChosenFS.place(x=102, y=210)

        lblFileCount = ttk.Label(rootScreen, text=len(self.root_files), background="#D9D9D9", font=("Roboto", 26))
        lblDirCount = ttk.Label(rootScreen, text=len(self.root_directories), background="#D9D9D9", font=("Roboto", 26))
        lblFileCount.place(x=113, y=680)
        lblDirCount.place(x=113, y=413)

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

    def specific_file(self):
        """
        Method - specific_file
        -------------------------
        Purpose - This method does the same as AllFileMeta, but for one,
        user chosen, file. It retrieves the same information and displays
        it in the same way.
        """

        self.ClearWindow()
        SpecFileScreen = self.__MainWindow
        SpecFileScreen.title(self.__title)
        SpecFileScreen.geometry(self.__screen_geometry)

        SpecFileScreen.attributes("-topmost", False)
        SpecFileScreen.resizable(False, False)
        background = ttk.Label(SpecFileScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__SpecFile, master=SpecFileScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        entryFileName = ttk.Entry(SpecFileScreen, textvariable=self.FileToDecode, background="#D9D9D9")
        entryFileName.place(x=46, y=293)

        btnMetadata = ttk.Button(SpecFileScreen, text=' Analyse ', command=self.specific_file)
        btnMetadata.place(x=46, y=393)

        lblBack = ttk.Button(SpecFileScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=46, y=493)

        if self.FileToDecode.get() is not None:
            if self.IsE01 is False:
                partition = pytsk3.FS_Info(self.diskimage, int(self.chosenOffset.get()))
            else:
                partition = pytsk3.FS_Info(self.img_info, int(self.chosenOffset.get()))

            file_obj = partition.open(self.FileToDecode.get())
            file_meta = file_obj.info.meta
            file_name = file_obj.info.name

            acc_time = datetime.utcfromtimestamp(file_meta.atime)
            crt_time = datetime.utcfromtimestamp(file_meta.crtime)
            meta_time = datetime.utcfromtimestamp(file_meta.ctime)
            mod_time = datetime.utcfromtimestamp(file_meta.mtime)

            lblType = ttk.Label(SpecFileScreen, text=file_name.type, background="#D9D9D9", font=("Roboto", 16))
            lblType.place(x=681, y=227)
            lblAddr = ttk.Label(SpecFileScreen, text=file_meta.addr, background="#D9D9D9", font=("Roboto", 16))
            lblAddr.place(x=971, y=227)
            lblAcc = ttk.Label(SpecFileScreen, text=acc_time, background="#D9D9D9", font=("Roboto", 16))
            lblAcc.place(x=341, y=511)
            lblCrt = ttk.Label(SpecFileScreen, text=crt_time, background="#D9D9D9", font=("Roboto", 16))
            lblCrt.place(x=753, y=511)
            lblMod = ttk.Label(SpecFileScreen, text=mod_time, background="#D9D9D9", font=("Roboto", 16))
            lblMod.place(x=1156, y=511)
            lblMeta = ttk.Label(SpecFileScreen, text=meta_time, background="#D9D9D9", font=("Roboto", 16))
            lblMeta.place(x=341, y=784)
            lblGID = ttk.Label(SpecFileScreen, text=file_meta.gid, background="#D9D9D9", font=("Roboto", 16))
            lblGID.place(x=816, y=784)
            lblSize = ttk.Label(SpecFileScreen, text=file_meta.size, background="#D9D9D9", font=("Roboto", 16))
            lblSize.place(x=1254, y=784)

            if file_meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                lblDel = ttk.Label(SpecFileScreen, text="Deleted", background="#D9D9D9", font=("Roboto", 16))
                lblDel.place(x=341, y=262)
            else:
                lblDel = ttk.Label(SpecFileScreen, text="Not Deleted", background="#D9D9D9", font=("Roboto", 16))
                lblDel.place(x=341, y=262)

    def Get_Specific_dir(self):
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

        lblChosenFS = ttk.Label(SpecDirScreen, text=self.chosenOffset.get(), background="#D9D9D9", font=("Roboto", 24))
        lblChosenFS.place(x=102, y=210)

        entryDir = ttk.Entry(SpecDirScreen, textvariable=self.DirToDecode)
        entryDir.place(x=88, y=835)

        btnDecode = ttk.Button(SpecDirScreen, text=' Decode ', command=self.Specific_dir)
        btnDecode.place(x=88, y=935)

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

        lblChosenFS = ttk.Label(SpecDirScreen, text=self.chosenOffset.get(), background="#D9D9D9", font=("Roboto", 24))
        lblChosenFS.place(x=102, y=210)

        btnBack = ttk.Button(SpecDirScreen, text=' back ', command=self.Get_Specific_dir)
        btnBack.place(x=88, y=935)

        if self.IsE01 is False:
            fs_info = pytsk3.FS_Info(self.diskimage, int(self.chosenOffset.get()))
        else:
            fs_info = pytsk3.FS_Info(self.img_info, int(self.chosenOffset.get()))

        directory = "/" + self.DirToDecode.get()
        print(directory)

        root_dir = fs_info.open_dir(directory)
        dir_count = 0
        file_count = 0
        file_in_dir = 0
        for file in root_dir:
            if file.info.meta != None:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    dir_count += 1
                    file_in_dir += 1
                    ascii_name = file.info.name.name.decode("ascii")
                    self.Specific_dir_subdir.append(ascii_name)
                else:
                    file_count += 1
                    ascii_name = file.info.name.name.decode("ascii")
                    self.Specific_dir_files.append(ascii_name)

        xcord = 1324
        ycord = 327
        for dir in self.Specific_dir_subdir:
            Label(SpecDirScreen, text=dir, background="#D9D9D9", font=("Roboto", 16)).place(x=xcord, y=ycord)
            ycord += 50

        root = self.__MainWindow
        frame = ScrollableFrame(700, 682, root)
        self.CurrentFrame = frame
        sCanvas = frame.getCanvas()

        frame.refreshCanvas(sCanvas)
        frame.place(x=378, y=300)

        rowPos = 90
        colPos = 5
        lineHeight = 25
        colFile = colPos

        textFileName = colFile + 10

        for file in self.Specific_dir_files:
            sCanvas.create_text(textFileName, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT,
                                anchor="nw",
                                text=file)
            rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=378, y=300)

        lblBack = ttk.Button(SpecDirScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=396, y=11)

        lblFileCount = ttk.Label(SpecDirScreen, text=len(self.Specific_dir_files), background="#D9D9D9",
                                 font=("Roboto", 26))
        lblDirCount = ttk.Label(SpecDirScreen, text=len(self.Specific_dir_subdir), background="#D9D9D9",
                                font=("Roboto", 26))
        lblFileCount.place(x=113, y=680)
        lblDirCount.place(x=113, y=413)

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

        exif = ExifTags()
        imgtags = exif.read_image_tags(self.EXIFfile.get())
        gpstags = exif.read_gps_tags(self.EXIFfile.get())

        lblMake = ttk.Label(exifScreen, text=imgtags[0], background="#D9D9D9", font=("Roboto", 16))
        lblMake.place(x=491, y=397)
        lblModel = ttk.Label(exifScreen, text=imgtags[1], background="#D9D9D9", font=("Roboto", 16))
        lblModel.place(x=491, y=485)
        lblSoftware = ttk.Label(exifScreen, text=imgtags[2], background="#D9D9D9", font=("Roboto", 16))
        lblSoftware.place(x=645, y=575)

        lblLatRef = ttk.Label(exifScreen, text=gpstags[0], background="#D9D9D9", font=("Roboto", 16))
        lblLatRef.place(x=1458, y=397)
        lblLat = ttk.Label(exifScreen, text=gpstags[1], background="#D9D9D9", font=("Roboto", 16))
        lblLat.place(x=1403, y=485)
        lblLongRef = ttk.Label(exifScreen, text=gpstags[2], background="#D9D9D9", font=("Roboto", 16))
        lblLongRef.place(x=1492, y=575)
        lblLong = ttk.Label(exifScreen, text=gpstags[3], background="#D9D9D9", font=("Roboto", 16))
        lblLong.place(x=1429, y=673)

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
        """
        Method - FileCarverComplete
        ----------------------------
        Purpose - This method is where the file is carved from the file system and
        saved to the chosen directory.self The method uses pytsk3's FS_Info.open
        to first locate the file and determine its size. It then reads the bytes of the
        file and stores them in a variable. It then writes these bytes to a file on the
        host computer.
        """

        self.ClearWindow()
        FileCarveScreen = self.__MainWindow
        FileCarveScreen.title(self.__title)
        FileCarveScreen.geometry(self.__screen_geometry)

        FileCarveScreen.attributes("-topmost", False)
        FileCarveScreen.resizable(False, False)
        background = ttk.Label(FileCarveScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__FileCarveDoneScreen, master=FileCarveScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        if self.IsE01 is True:
            filesys = pytsk3.FS_Info(self.img_info, int(self.chosenOffset.get()))
        else:
            filesys = pytsk3.FS_Info(self.diskimage, int(self.chosenOffset.get()))

        file = filesys.open(self.FileToCarve.get())
        filebytes = file.read_random(0, file.info.meta.size)

        f = open("Carved File", "x")
        f.close()

        try:
            with open("Carved File", 'wb') as carvedfile:
                carvedfile.write(filebytes)
        except:
            messagebox.showerror("ERROR", "An error occurred opening the file!")

        btnBack = ttk.Button(FileCarveScreen, text=" Back ", command=self.FileCarver)
        btnBack.place(x=42, y=317)

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

        entryFname = ttk.Entry(GetHashScreen, textvariable=self.HashFile)
        entryFname.place(x=156, y=118)
        entryHash = ttk.Entry(GetHashScreen, textvariable=self.UserHash)
        entryHash.place(x=156, y=398)
        btnCompare = ttk.Button(GetHashScreen, text=" SHA256 ", command=self.SHA_hashing)
        btnCompare.place(x=156, y=500)
        btnCompare = ttk.Button(GetHashScreen, text=" MD5 ", command=self.MD5_hashing)
        btnCompare.place(x=156, y=570)
        btnHelp = ttk.Button(GetHashScreen, text=' Whats this? ', command=partial(self.display_msg, "GetHashScreen"))
        btnHelp.place(x=1777, y=15)

    def MD5_hashing(self):
        self.ClearWindow()
        HashCompareScreen = self.__MainWindow
        HashCompareScreen.title(self.__title)
        HashCompareScreen.geometry(self.__screen_geometry)

        HashCompareScreen.attributes("-topmost", False)
        HashCompareScreen.resizable(False, False)
        background = ttk.Label(HashCompareScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__HashingScreen, master=HashCompareScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        lblBack = ttk.Button(HashCompareScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=396, y=1024)

        if self.IsE01 is True:
            hashing = HashVerify(self.img_info, int(self.chosenOffset.get()))
        else:
            hashing = HashVerify(self.diskimage, int(self.chosenOffset.get()))

        comparison = hashing.md5_compare(self.HashFile.get(), self.UserHash.get().upper())

        if comparison is True:
            Label(HashCompareScreen, text="Hashes match, integrity verified!", background="#D9D9D9",
                  font=("Roboto", 26)).place(x=590, y=240)
        else:
            Label(HashCompareScreen, text="Hashes don't match, integrity can't be verified!", background="#D9D9D9",
                  font=("Roboto", 26)).place(x=590, y=240)

    def SHA_hashing(self):
        self.ClearWindow()
        HashCompareScreen = self.__MainWindow
        HashCompareScreen.title(self.__title)
        HashCompareScreen.geometry(self.__screen_geometry)

        HashCompareScreen.attributes("-topmost", False)
        HashCompareScreen.resizable(False, False)
        background = ttk.Label(HashCompareScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.__HashingScreen, master=HashCompareScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        lblBack = ttk.Button(HashCompareScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=396, y=1024)

        if self.IsE01 is True:
            hashing = HashVerify(self.img_info, int(self.chosenOffset.get()))
        else:
            hashing = HashVerify(self.diskimage, int(self.chosenOffset.get()))

        comparison = hashing.sha_compare(self.HashFile.get(), self.UserHash.get().upper())

        if comparison is True:
            Label(HashCompareScreen, text="Hashes match, integrity verified!", background="#D9D9D9",
                  font=("Roboto", 26))
        else:
            Label(HashCompareScreen, text="Hashes don't match, integrity can't be verified!", background="#D9D9D9",
                  font=("Roboto", 26))

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

        btnCarve = ttk.Button(CarveTypeScreen, text=' Carve ', command=self.CarveTypeSystem)
        btnCarve.place(x=894, y=400)

        btnSystem = ttk.Button(CarveTypeScreen, text=' Carve system files', command=self.CarveTypeComplete)
        btnSystem.place(x=894, y=735)

    def CarveTypeSystem(self):
        dirname = f"{self.ChosenFile.get()}-File System files"
        path = os.path.join("APDF Log", dirname)
        os.mkdir(path)

        count = 1
        for offset in self.workingOffsets:
            if self.IsE01 is True:
                filesys = pytsk3.FS_Info(self.img_info, offset)
            else:
                filesys = pytsk3.FS_Info(self.diskimage, offset)

            root_dir = filesys.open_dir(inode=filesys.info.root_inum)
            for file in root_dir:
                if file.info.meta != None:
                    if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        ascii_name = file.info.name.name.decode("ascii")
                        dir_name = "/" + ascii_name
                        dir = filesys.open_dir(dir_name)
                        for file in dir:
                            if file.info.meta != None:
                                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                                    pass
                                else:
                                    ascii_name = file.info.name.name.decode("ascii")
                                    file = filesys.open(self.FileToCarve.get())
                                    filebytes = file.read_random(0, file.info.meta.size)

                                    for name in self.filesystemfiles:
                                        if name.upper() == ascii_name:
                                            try:
                                                carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count})"
                                                f = open(carvedname, "x")
                                                f.close()
                                            except:
                                                count += 1
                                                carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count})"
                                                f = open(carvedname, "x")
                                                f.close()

                                            try:
                                                with open(carvedname, 'wb') as carvedfile:
                                                    carvedfile.write(filebytes)
                                            except:
                                                messagebox.showerror("ERROR", "An error occurred opening the file!")

                                        else:
                                            pass

                                    else:
                                        pass

                    else:
                        ascii_name = file.info.name.name.decode("ascii")
                        file = filesys.open(self.FileToCarve.get())
                        filebytes = file.read_random(0, file.info.meta.size)
                        for name in self.filesystemfiles:
                            if name.upper() == ascii_name:
                                try:
                                    carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count})"
                                    f = open(carvedname, "x")
                                    f.close()
                                except:
                                    count += 1
                                    carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count})"
                                    f = open(carvedname, "x")
                                    f.close()

                                try:
                                    with open(carvedname, 'wb') as carvedfile:
                                        carvedfile.write(filebytes)
                                except:
                                    messagebox.showerror("ERROR", "An error occurred opening the file!")

                        else:
                            pass

        messagebox.showinfo("Carve all", f"Your files were successfully carved\n and saved to: {path}")

    def CarveTypeComplete(self):
        ftype = self.file_type.get().replace(".", "")
        dirname = f"{self.ChosenFile.get()}-{ftype.upper()} files"
        path = os.path.join("APDF Log", dirname)
        os.mkdir(path)

        count = 1
        for offset in self.workingOffsets:
            if self.IsE01 is True:
                filesys = pytsk3.FS_Info(self.img_info, offset)
            else:
                filesys = pytsk3.FS_Info(self.diskimage, offset)

            root_dir = filesys.open_dir(inode=filesys.info.root_inum)
            for file in root_dir:
                if file.info.meta != None:
                    if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        ascii_name = file.info.name.name.decode("ascii")
                        dir_name = "/" + ascii_name
                        dir = filesys.open_dir(dir_name)
                        for file in dir:
                            if file.info.meta != None:
                                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                                    pass
                                else:
                                    ascii_name = file.info.name.name.decode("ascii")
                                    file = filesys.open(self.FileToCarve.get())
                                    filebytes = file.read_random(0, file.info.meta.size)
                                    extension = GetExt(ascii_name)
                                    if extension.get() is None:
                                        ext = ""
                                    else:
                                        ext = extension.get()

                                    if ext.upper() == self.file_type.get().upper():

                                        try:
                                            carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count}){ext}"
                                            f = open(carvedname, "x")
                                            f.close()
                                        except:
                                            count += 1
                                            carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count}){ext}"
                                            f = open(carvedname, "x")
                                            f.close()

                                        try:
                                            with open(carvedname, 'wb') as carvedfile:
                                                carvedfile.write(filebytes)
                                        except:
                                            messagebox.showerror("ERROR", "An error occurred opening the file!")

                                    else:
                                        pass

                    else:
                        ascii_name = file.info.name.name.decode("ascii")
                        file = filesys.open(self.FileToCarve.get())
                        filebytes = file.read_random(0, file.info.meta.size)
                        extension = GetExt(ascii_name)
                        if extension.get() is None:
                            ext = ""
                        else:
                            ext = extension.get()

                        if ext.upper() == self.file_type.get().upper():

                            try:
                                carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count}){ext}"
                                f = open(carvedname, "x")
                                f.close()
                            except:
                                count += 1
                                carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count}){ext}"
                                f = open(carvedname, "x")
                                f.close()

                            try:
                                with open(carvedname, 'wb') as carvedfile:
                                    carvedfile.write(filebytes)
                            except:
                                messagebox.showerror("ERROR", "An error occurred opening the file!")

                        else:
                            pass

        messagebox.showinfo("Carve all", f"Your files were successfully carved\n and saved to: {path}")

    def CarveAll(self):
        try:
            dirname = f"{self.ChosenFile.get()}-All Carved files"
            path = os.path.join("APDF Log", dirname)
            os.mkdir(path)
        except:
            dirname = "APDF Log"
            path = os.getcwd() + "\\" + dirname

        count = 1
        for offset in self.workingOffsets:
            if self.IsE01 is True:
                filesys = pytsk3.FS_Info(self.img_info, offset)
            else:
                filesys = pytsk3.FS_Info(self.diskimage, offset)

            root_dir = filesys.open_dir(inode=filesys.info.root_inum)
            for file in root_dir:
                if file.info.meta != None:
                    if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        ascii_name = file.info.name.name.decode("ascii")
                        dir_name = "/" + ascii_name
                        dir = filesys.open_dir(dir_name)
                        for file in dir:
                            if file.info.meta != None:
                                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                                    pass
                                else:
                                    ascii_name = file.info.name.name.decode("ascii")
                                    file = filesys.open(self.FileToCarve.get())
                                    filebytes = file.read_random(0, file.info.meta.size)
                                    extension = GetExt(ascii_name)
                                    if extension.get() is None:
                                        ext = ""
                                    else:
                                        ext = extension.get()

                                    try:
                                        carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count}){ext}"
                                        f = open(carvedname, "x")
                                        f.close()
                                    except:
                                        count += 1
                                        carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count}){ext}"
                                        f = open(carvedname, "x")
                                        f.close()

                                    try:
                                        with open(carvedname, 'wb') as carvedfile:
                                            carvedfile.write(filebytes)
                                    except:
                                        messagebox.showerror("ERROR", "An error occurred opening the file!")

                    else:
                        ascii_name = file.info.name.name.decode("ascii")
                        file = filesys.open(self.FileToCarve.get())
                        filebytes = file.read_random(0, file.info.meta.size)
                        extension = GetExt(ascii_name)
                        if extension.get() is None:
                            ext = ""
                        else:
                            ext = extension.get()

                        try:
                            carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count}){ext}"
                            f = open(carvedname, "x")
                            f.close()
                        except:
                            count += 1
                            carvedname = f"{path}/Carved file - {ascii_name} from {offset} ({count}){ext}"
                            f = open(carvedname, "x")
                            f.close()

                        try:
                            with open(carvedname, 'wb') as carvedfile:
                                carvedfile.write(filebytes)
                        except:
                            messagebox.showerror("ERROR", "An error occurred opening the file!")

        messagebox.showinfo("Carve all", f"Your files were successfuly carved\n and saved to: {path}")


"""This is where the program is ran from, it instantiates the class"""
if __name__ == '__main__':
    c = ForensicGui()
    c.first_screen()
