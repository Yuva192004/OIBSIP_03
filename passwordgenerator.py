import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")

        # Password length label and entry
        self.label_length = ttk.Label(master, text="Password Length:")
        self.label_length.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.password_length = tk.IntVar()
        self.entry_length = ttk.Entry(master, textvariable=self.password_length)
        self.entry_length.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.entry_length.insert(0, "12")  # Default length

        # Password complexity label and dropdown
        self.label_complexity = ttk.Label(master, text="Password Complexity:")
        self.label_complexity.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.complexity_options = ["Easy", "Medium", "Hard"]
        self.complexity_var = tk.StringVar(value="Medium")
        self.complexity_menu = ttk.Combobox(master, textvariable=self.complexity_var, values=self.complexity_options)
        self.complexity_menu.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Generate button
        self.generate_button = ttk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

        # Generated password label and entry
        self.password_label = ttk.Label(master, text="Generated Password:")
        self.password_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(master, textvariable=self.password_var, state="readonly")
        self.password_entry.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        # Copy to clipboard button
        self.copy_button = ttk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.grid(row=4, column=0, columnspan=2, padx=10, pady=5)

    def generate_password(self):
        length = self.password_length.get()
        complexity = self.complexity_var.get()

        if length <= 0:
            messagebox.showerror("Error", "Password length must be a positive integer.")
            return

        if complexity == "Easy":
            characters = string.ascii_letters + string.digits
        elif complexity == "Medium":
            characters = string.ascii_letters + string.digits + string.punctuation
        else:
            characters = string.ascii_letters + string.digits + string.punctuation + string.ascii_uppercase

        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_var.set(password)

    def copy_to_clipboard(self):
        password = self.password_var.get()
        pyperclip.copy(password)
        messagebox.showinfo("Password Generator", "Password copied to clipboard!")

def main():
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
