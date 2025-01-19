import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import threading
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext, Frame, Entry, Button, messagebox
import bcrypt
import json
import os

# AES encryption key (must match the server's key)
key = b'16bytekey1234567'  # Replace with a secure key in a real application

# File to store user credentials
USERS_FILE = "users.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file)

def register_user(username, password):
    users = load_users()
    if username in users:
        return False  # User already exists
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users[username] = hashed_password.decode()
    save_users(users)
    return True

def authenticate_user(username, password):
    users = load_users()
    if username in users:
        hashed_password = users[username].encode()
        return bcrypt.checkpw(password.encode(), hashed_password)
    return False

def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return encrypted_message

def decrypt_message(encrypted_message):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_message.decode()

def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.root.geometry("300x200")

        # Username
        self.username_label = tk.Label(root, text="Username:")
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(root)
        self.username_entry.pack(pady=5)

        # Password
        self.password_label = tk.Label(root, text="Password:")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack(pady=5)

        # Login button
        self.login_button = tk.Button(root, text="Login", command=self.login)
        self.login_button.pack(pady=10)

        # Register button
        self.register_button = tk.Button(root, text="Register", command=self.register)
        self.register_button.pack(pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if authenticate_user(username, password):
            messagebox.showinfo("Login Successful", "Welcome to the chat!")
            self.root.destroy()  # Close the login window
            # Open the chat window
            chat_root = tk.Tk()
            chat_gui = ClientGUI(chat_root, username)
            chat_root.mainloop()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username and password:
            if register_user(username, password):
                messagebox.showinfo("Registration Successful", "User registered successfully!")
            else:
                messagebox.showerror("Registration Failed", "Username already exists.")
        else:
            messagebox.showerror("Registration Failed", "Username and password cannot be empty.")

class ClientGUI:
    def __init__(self, root, username):
        self.root = root
        self.root.title("Encrypted Chat Client")
        self.root.geometry("500x400")
        self.username = username

        # Chat display area
        self.chat_area = scrolledtext.ScrolledText(root, state='disabled')
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Input frame
        self.input_frame = Frame(root)
        self.input_frame.pack(padx=10, pady=10, fill=tk.X)

        # Input field
        self.input_field = Entry(self.input_frame)
        self.input_field.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.input_field.bind("<Return>", self.send_message)

        # Send button
        self.send_button = Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        # Connect to server
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(('127.0.0.1', 12345))
        self.display_message(f"[{get_timestamp()}] Connected to server.")

        # Start threads
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

    def display_message(self, message):
        self.root.after(0, self.update_chat_area, message)  # Schedule GUI update

    def update_chat_area(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def send_message(self, event=None):
        message = self.input_field.get()
        if message:
            encrypted_message = encrypt_message(message)
            self.client.send(encrypted_message)
            self.display_message(f"[{get_timestamp()}] You: {message}")
            self.input_field.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                encrypted_data = self.client.recv(1024)
                if not encrypted_data:
                    break
                decrypted_message = decrypt_message(encrypted_data)
                self.display_message(f"[{get_timestamp()}] Received: {decrypted_message}")
            except Exception as e:
                self.display_message(f"[{get_timestamp()}] Error receiving message: {e}")
                break

if __name__ == '__main__':
    root = tk.Tk()
    login_gui = LoginWindow(root)
    root.mainloop()