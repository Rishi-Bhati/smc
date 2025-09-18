import tkinter as tk
from tkinter import ttk

#main window setup...
root = tk.Tk()
root.title("SMC Maker")
root.geometry("500x300")


#creating a notebook to manage tabs and place in root window...

notebook = tk.ttk.Notebook(root)
notebook.pack(pady=10, padx=10, fill="both", expand=True)

#creating frames for generate keys and make smc tabs

genkey_frame = ttk.Frame(notebook)
create_frame = ttk.Frame(notebook)

#add frames to notebook as tabs
notebook.add(genkey_frame, text="Generate Keys")
notebook.add(create_frame, text="Create SMC")

root.mainloop()