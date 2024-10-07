import base64
import tkinter as tk
from tkinter import messagebox
import pyperclip
import os
import pickle

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
        
        # Reload password list
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
    password_listbox.delete(0, tk.END)
    passwords = load_passwords()
    for description, password in passwords:
        password_listbox.insert(tk.END, f"{description}:{password}")

def delete_password():
    selected_index = password_listbox.curselection()
    if selected_index:
        passwords = load_passwords()
        del passwords[selected_index[0]]
        with open("passwords.bin", "wb") as file:
            pickle.dump(passwords, file)
        display_passwords()
        messagebox.showinfo("Success", "Password deleted successfully!")
    else:
        messagebox.showwarning("Error", "No password selected.")

def edit_password():
    selected_index = password_listbox.curselection()
    if selected_index:
        passwords = load_passwords()
        selected_password = passwords[selected_index[0]]
        description, password = selected_password
        description_entry.delete(0, tk.END)
        description_entry.insert(0, description)
        result_entry.delete(0, tk.END)
        result_entry.insert(0, password)
        del passwords[selected_index[0]]
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
        messagebox.showwarning("Error", "No password selected.")

def toggle_password_visibility():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        toggle_button.config(text="Hide")
    else:
        password_entry.config(show='*')
        toggle_button.config(text="Show")

def copy_from_listbox():
    selected_index = password_listbox.curselection()
    if selected_index:
        selected_password = password_listbox.get(selected_index).split(":")[1]
        pyperclip.copy(selected_password)
        messagebox.showinfo("Success", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Error", "No password selected.")

root = tk.Tk()
root.title("Password Manager")

# Left side frame
left_frame = tk.Frame(root)
left_frame.pack(side=tk.LEFT, padx=10, pady=10)

password_label = tk.Label(left_frame, text="Enter Password:")
password_label.pack(pady=5)

password_frame = tk.Frame(left_frame)
password_frame.pack(pady=5)

password_entry = tk.Entry(password_frame, width=30, show="*")
password_entry.pack(side=tk.LEFT)

toggle_button = tk.Button(password_frame, text="Show", command=toggle_password_visibility)
toggle_button.pack(side=tk.LEFT, padx=5)

shift_label = tk.Label(left_frame, text="Enter Shift (Caesar Cipher):")
shift_label.pack(pady=5)

shift_entry = tk.Entry(left_frame, width=40)
shift_entry.pack(pady=5)

description_label = tk.Label(left_frame, text="Description:")
description_label.pack(pady=5)

description_entry = tk.Entry(left_frame, width=40)
description_entry.pack(pady=5)

encrypt_button = tk.Button(left_frame, text="Encrypt", command=encrypt_password)
encrypt_button.pack(pady=10)

result_label = tk.Label(left_frame, text="Encryption result:")
result_label.pack(pady=5)

result_entry = tk.Entry(left_frame, width=40)
result_entry.pack(pady=5)

copy_button = tk.Button(left_frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack(pady=10)

save_button = tk.Button(left_frame, text="Save Password", command=save_password)
save_button.pack(pady=10)

# Right side frame
right_frame = tk.Frame(root)
right_frame.pack(side=tk.RIGHT, padx=10, pady=10)

password_listbox = tk.Listbox(right_frame, width=40)
password_listbox.pack(pady=5)

copy_listbox_button = tk.Button(right_frame, text="Copy Selected Password", command=copy_from_listbox)
copy_listbox_button.pack(pady=5)

edit_button = tk.Button(right_frame, text="Edit Selected Password", command=edit_password)
edit_button.pack(pady=5)

delete_button = tk.Button(right_frame, text="Delete Selected Password", command=delete_password)
delete_button.pack(pady=5)

# Load passwords when the program starts
display_passwords()

root.mainloop()
