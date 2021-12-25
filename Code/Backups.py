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

        btnHelp = ttk.Button(rootScreen, text=' Whats this? ', command=partial(self.display_msg, "rootScreen"))
        btnHelp.place(x=1777, y=15)

        lblChosenFS = ttk.Label(rootScreen, text=self.chosenOffset.get(), background="#D9D9D9", font=("Roboto", 24))
        lblChosenFS.place(x=102, y=210)

        if len(self.file_list) > 0:
            pass

        else:
            if self.IsE01 is False:
                fs_info = pytsk3.FS_Info(self.diskimage, int(self.chosenOffset.get()))
            else:
                fs_info = pytsk3.FS_Info(self.img_info, int(self.chosenOffset.get()))

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

        xcord = 1324
        ycord = 327
        for dir in self.dir_names:
            Label(rootScreen, text=dir, background="#D9D9D9", font=("Roboto", 16)).place(x=xcord, y=ycord)
            ycord += 50

        root = self.__MainWindow
        frame = ScrollableFrame(700, 682, root)
        self.CurrentFrame = frame
        sCanvas = frame.getCanvas()

        rowPos = 90
        colPos = 5
        lineHeight = 25
        colFile = colPos

        textFileName = colFile + 10

        for file in self.file_list:
            sCanvas.create_text(textFileName, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=file)
            rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=378, y=300)

        lblBack = ttk.Button(rootScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=396, y=11)

        lblFileCount = ttk.Label(rootScreen, text=len(self.file_list), background="#D9D9D9", font=("Roboto", 26))
        lblDirCount = ttk.Label(rootScreen, text=len(self.dir_names), background="#D9D9D9", font=("Roboto", 26))
        lblFileCount.place(x=113, y=680)
        lblDirCount.place(x=113, y=413)









"root analysis"
"-----------------"

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

        connection = sqlite3.connect("APDF Log\\APDF report.db")
        cursor = connection.cursor()

        qry_total_row = """SELECT * FROM Partitions"""
        cursor.execute(qry_total_row)
        result = cursor.fetchall()
        total_rows = len(result)

        for file in self.file_list:
            name = file
            qry_ftype = f"""SELECT Type FROM RootMeta WHERE Name={name}"""
            cursor.execute(qry_ftype)
            file_type = cursor.fetchall()

            qry_metaNum = f"""SELECT MetaRecordNum FROM RootMeta WHERE Name={name}"""
            cursor.execute(qry_metaNum)
            MetaNum = cursor.fetchall()

            qry_accTime = f"""SELECT AccessTime FROM RootMeta WHERE Name={name}"""
            cursor.execute(qry_accTime)
            AccTime = cursor.fetchall()

            qry_CrtTime = f"""SELECT CreateTime FROM RootMeta WHERE Name={name}"""
            cursor.execute(qry_CrtTime)
            CrtTime = cursor.fetchall()

            qry_modtime = f"""SELECT MetaRecordNum FROM RootMeta WHERE Name={name}"""
            cursor.execute(qry_modtime)
            ModTime = cursor.fetchall()

            qry_metaTime = f"""SELECT MetaRecordNum FROM RootMeta WHERE Name={name}"""
            cursor.execute(qry_metaTime)
            MetaTime = cursor.fetchall()

            qry_owner = f"""SELECT MetaRecordNum FROM RootMeta WHERE Name={name}"""
            cursor.execute(qry_owner)
            GID = cursor.fetchall()

            qry_size = f"""SELECT MetaRecordNum FROM RootMeta WHERE Name={name}"""
            cursor.execute(qry_size)
            size = cursor.fetchall()

            qry_deleted = f"""SELECT MetaRecordNum FROM RootMeta WHERE Name={name}"""
            cursor.execute(qry_deleted)
            deleted = cursor.fetchall()



        xcord = 1324
        ycord = 327
        for dir in self.dir_names:
            Label(rootScreen, text=dir, background="#D9D9D9", font=("Roboto", 16)).place(x=xcord, y=ycord)
            ycord += 50

        btnHelp = ttk.Button(rootScreen, text=' Whats this? ', command=partial(self.display_msg, "rootScreen"))
        btnHelp.place(x=1777, y=15)

        lblChosenFS = ttk.Label(rootScreen, text=self.chosenOffset.get(), background="#D9D9D9", font=("Roboto", 24))
        lblChosenFS.place(x=102, y=210)

        xcord = 1324
        ycord = 327
        for dir in self.dir_names:
            Label(rootScreen, text=dir, background="#D9D9D9", font=("Roboto", 16)).place(x=xcord, y=ycord)
            ycord += 50

        root = self.__MainWindow
        frame = ScrollableFrame(700, 682, root)
        self.CurrentFrame = frame
        sCanvas = frame.getCanvas()

        rowPos = 90
        colPos = 5
        lineHeight = 25
        colFile = colPos

        textFileName = colFile + 10

        for file in self.file_list:
            sCanvas.create_text(textFileName, rowPos, font=("Roboto", 16), fill="#000000", justify=LEFT, anchor="nw",
                                text=file)
            rowPos = rowPos + lineHeight

        frame.refreshCanvas(sCanvas)
        frame.place(x=378, y=300)

        lblBack = ttk.Button(rootScreen, text=" Back ", command=self.MainScreen)
        lblBack.place(x=396, y=11)

        lblFileCount = ttk.Label(rootScreen, text=len(self.file_list), background="#D9D9D9", font=("Roboto", 26))
        lblDirCount = ttk.Label(rootScreen, text=len(self.dir_names), background="#D9D9D9", font=("Roboto", 26))
        lblFileCount.place(x=113, y=680)
        lblDirCount.place(x=113, y=413)







