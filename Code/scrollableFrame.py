import tkinter as tk
from tkinter import ttk


class ScrollableFrame(tk.Frame):
    """
    *******************************************************************************************************
    Class - ScrollableFrame
    *******************************************************************************************************
    description:
        The scrollable frame class is used to set up a scrollable tkinter frame
        This scrollable frame was taken and then modified from here:
        Scrollable Frames in Tkinter - Jose Salvatierra - https://blog.tecladocode.com/tkinter-scrollable-frames/
      
    attributes:
      
      private attributes:
        - none
      w - 682
      h - 700
      public attributes:
    """

    def __init__(self, height, width, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self,  width = width, height = height, bg='#D9D9D9', borderwidth=0, highlightthickness=0)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, width=600)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        

    def refreshCanvas(self, sCanvas):
        sCanvas.configure(scrollregion=sCanvas.bbox("all"))

    def getCanvas(self):
        return self.canvas

