import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import threading
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext, Frame, Entry, Button

# AES encryption key (must be 16, 24, or 32 bytes long)
key = b'16bytekey1234567'  # Replace with a secure key in a real application

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

def save_message(message):
    with open("chat_history.txt", "a") as file:
        file.write(message + "\n")

def load_message_history():
    try:
        with open("chat_history.txt", "r") as file:
            return file.readlines()
    except FileNotFoundError:
        return []

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Chat Server")
        self.root.geometry("500x400")

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

        # Server setup
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(('127.0.0.1', 12345))
        self.server.listen(1)
        self.display_message(f"[{get_timestamp()}] Server listening on port 12345...")

        # Accept a connection
        self.client, self.addr = self.server.accept()
        self.display_message(f"[{get_timestamp()}] Connection from {self.addr}")

        # Load and display message history
        self.display_message_history()

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

    def display_message_history(self):
        history = load_message_history()
        for message in history:
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, message)
            self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def send_message(self, event=None):
        message = self.input_field.get()
        if message:
            encrypted_message = encrypt_message(message)
            self.client.send(encrypted_message)
            save_message(f"[{get_timestamp()}] You: {message}")  # Save sent message
            self.display_message(f"[{get_timestamp()}] You: {message}")
            self.input_field.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                encrypted_data = self.client.recv(1024)
                if not encrypted_data:
                    break
                decrypted_message = decrypt_message(encrypted_data)
                save_message(f"[{get_timestamp()}] Received: {decrypted_message}")  # Save received message
                self.display_message(f"[{get_timestamp()}] Received: {decrypted_message}")
            except Exception as e:
                self.display_message(f"[{get_timestamp()}] Error receiving message: {e}")
                break

if __name__ == '__main__':
    root = tk.Tk()
    gui = ServerGUI(root)
    root.mainloop()