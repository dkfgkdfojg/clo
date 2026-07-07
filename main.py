# main.py
import tkinter as tk
import customtkinter as ctk
from gui.app import OSINTApp

if __name__ == "__main__":
    root = ctk.CTk()
    app = OSINTApp(root)
    root.mainloop()
