import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import os

SERVER_URL = "http://127.0.0.1:5000/upload-and-decode"

def send_file():
    path = filedialog.askopenfilename()
    if not path:
        return
    mode = mode_var.get()
    reen = re_var.get()
    fd = {"file": open(path, "rb")}
    data = {"mode": mode, "re_encrypt": str(reen)}
    r = requests.post(SERVER_URL, files=fd, data=data)
    res = r.json()
    if not res.get("success"):
        messagebox.showerror("Error", res.get("error"))
    else:
        result_text.set(f"Decoded: {res['decoded_message']}\n\nBot: {res['bot_reply']}")
        if res.get("reply_stego_path"):
            messagebox.showinfo("Reply", f"Reply stego saved at {res['reply_stego_path']}")

root = tk.Tk()
root.title("StegaBot Desktop")
tk.Label(root, text="Select Mode:").pack()
mode_var = tk.StringVar()
tk.OptionMenu(root, mode_var, "text", "image", "audio", "video").pack()
re_var = tk.BooleanVar()
tk.Checkbutton(root, text="Re-encode bot reply", variable=re_var).pack()
tk.Button(root, text="Select and Send Stego File", command=send_file).pack(pady=10)
result_text = tk.StringVar()
tk.Label(root, textvariable=result_text, wraplength=400, justify="left").pack()
root.mainloop()
