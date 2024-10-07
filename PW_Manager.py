import base64
import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip
import os
import pickle
from ttkthemes import ThemedTk

def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

def base64_encode(text):
    encoded_bytes = base64.b64encode(text.encode())
    return encoded_bytes.decode('utf-8')

def save_password():
    password = result_entry.get()
    description = description_entry.get()
    if password and description:
        passwords = load_passwords()
        passwords.append((description, password))
        with open("passwords.bin", "wb") as file:
            pickle.dump(passwords, file)
        messagebox.showinfo("Success", "Password saved successfully!")
        
        password_entry.delete(0, tk.END)
        shift_entry.delete(0, tk.END)
        description_entry.delete(0, tk.END)
        result_entry.delete(0, tk.END)
        
        display_passwords()
    else:
        messagebox.showwarning("Error", "Field cannot be empty.")

def load_passwords():
    if os.path.exists("passwords.bin"):
        with open("passwords.bin", "rb") as file:
            return pickle.load(file)
    else:
        return []

def display_passwords():
    password_tree.delete(*password_tree.get_children())
    passwords = load_passwords()
    for i, (description, password) in enumerate(passwords):
        password_tree.insert("", "end", values=(i+1, description, password))

def delete_password():
    selected_item = password_tree.selection()
    if selected_item:
        item = password_tree.item(selected_item)
        index = int(item['values'][0]) - 1
        passwords = load_passwords()
        del passwords[index]
        with open("passwords.bin", "wb") as file:
            pickle.dump(passwords, file)
        display_passwords()
        messagebox.showinfo("Success", "Password deleted successfully!")
    else:
        messagebox.showwarning("Error", "No password selected.")

def edit_password():
    selected_item = password_tree.selection()
    if selected_item:
        item = password_tree.item(selected_item)
        index = int(item['values'][0]) - 1
        passwords = load_passwords()
        selected_password = passwords[index]
        description, password = selected_password
        description_entry.delete(0, tk.END)
        description_entry.insert(0, description)
        result_entry.delete(0, tk.END)
        result_entry.insert(0, password)
        del passwords[index]
        with open("passwords.bin", "wb") as file:
            pickle.dump(passwords, file)
        display_passwords()
        messagebox.showinfo("Edit", "Please edit and re-save your password.")
    else:
        messagebox.showwarning("Error", "No password selected.")

def encrypt_password():
    password = password_entry.get()
    shift = int(shift_entry.get())
    caesar_encrypted = caesar_encrypt(password, shift)
    base64_encrypted = base64_encode(caesar_encrypted)
    result_entry.delete(0, tk.END)
    result_entry.insert(0, base64_encrypted)

def copy_to_clipboard():
    encrypted_password = result_entry.get()
    if encrypted_password:
        pyperclip.copy(encrypted_password)
        messagebox.showinfo("Success", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Error", "No password to copy.")

def toggle_password_visibility():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        toggle_button.config(text="Hide")
    else:
        password_entry.config(show='*')
        toggle_button.config(text="Show")

def copy_from_tree():
    selected_item = password_tree.selection()
    if selected_item:
        item = password_tree.item(selected_item)
        selected_password = item['values'][2]
        pyperclip.copy(selected_password)
        messagebox.showinfo("Success", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Error", "No password selected.")

root = ThemedTk(theme="arc")
root.title("Password Manager")
root.geometry("800x600")
root.resizable(True, True)

style = ttk.Style()
style.configure("TButton", padding=6, relief="flat", background="#ccc")

main_frame = ttk.Frame(root, padding="20 20 20 20")
main_frame.pack(fill=tk.BOTH, expand=True)

left_frame = ttk.Frame(main_frame)
left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

right_frame = ttk.Frame(main_frame)
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Left side (Inputs)
input_frame = ttk.LabelFrame(left_frame, text="Password Encryption", padding="10 10 10 10")
input_frame.pack(fill=tk.BOTH, expand=True)

ttk.Label(input_frame, text="Enter Password:").grid(row=0, column=0, sticky="w", pady=5)
password_frame = ttk.Frame(input_frame)
password_frame.grid(row=1, column=0, columnspan=2, sticky="we", pady=5)
password_entry = ttk.Entry(password_frame, show="*", width=30)
password_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
toggle_button = ttk.Button(password_frame, text="Show", command=toggle_password_visibility, width=10)
toggle_button.pack(side=tk.RIGHT, padx=(5, 0))

ttk.Label(input_frame, text="Enter Shift (Caesar Cipher):").grid(row=2, column=0, sticky="w", pady=5)
shift_entry = ttk.Entry(input_frame, width=10)
shift_entry.grid(row=3, column=0, sticky="w", pady=5)

ttk.Label(input_frame, text="Description:").grid(row=4, column=0, sticky="w", pady=5)
description_entry = ttk.Entry(input_frame, width=40)
description_entry.grid(row=5, column=0, columnspan=2, sticky="we", pady=5)

encrypt_button = ttk.Button(input_frame, text="Encrypt", command=encrypt_password)
encrypt_button.grid(row=6, column=0, sticky="w", pady=10)

ttk.Label(input_frame, text="Encryption result:").grid(row=7, column=0, sticky="w", pady=5)
result_entry = ttk.Entry(input_frame, width=40)
result_entry.grid(row=8, column=0, columnspan=2, sticky="we", pady=5)

button_frame = ttk.Frame(input_frame)
button_frame.grid(row=9, column=0, columnspan=2, sticky="we", pady=10)
copy_button = ttk.Button(button_frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack(side=tk.LEFT, padx=(0, 5))
save_button = ttk.Button(button_frame, text="Save Password", command=save_password)
save_button.pack(side=tk.LEFT)

# Right side (Password List)
list_frame = ttk.LabelFrame(right_frame, text="Saved Passwords", padding="10 10 10 10")
list_frame.pack(fill=tk.BOTH, expand=True)

password_tree = ttk.Treeview(list_frame, columns=("ID", "Description", "Password"), show="headings", selectmode="browse")
password_tree.heading("ID", text="#")
password_tree.heading("Description", text="Description")
password_tree.heading("Password", text="Password")
password_tree.column("ID", width=30)
password_tree.column("Description", width=150)
password_tree.column("Password", width=200)
password_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=password_tree.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
password_tree.configure(yscrollcommand=scrollbar.set)

tree_button_frame = ttk.Frame(right_frame)
tree_button_frame.pack(fill=tk.X, pady=10)
copy_tree_button = ttk.Button(tree_button_frame, text="Copy Selected", command=copy_from_tree)
copy_tree_button.pack(side=tk.LEFT, padx=(10, 5))
edit_button = ttk.Button(tree_button_frame, text="Edit Selected", command=edit_password)
edit_button.pack(side=tk.LEFT, padx=(0, 5))
delete_button = ttk.Button(tree_button_frame, text="Delete Selected", command=delete_password)
delete_button.pack(side=tk.LEFT)

# Load passwords when the program starts
display_passwords()

root.mainloop()