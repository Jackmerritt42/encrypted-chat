# Encrypted Chat Application

A secure, encrypted chat application with a GUI, user authentication, and message history. Built with Python, Tkinter, and AES encryption.

---

## Features

- **End-to-End Encryption:** Messages are encrypted using AES (Advanced Encryption Standard) before transmission.
- **User Authentication:** Users can register and log in securely using bcrypt for password hashing.
- **Message History:** Chat history is saved and displayed when users reconnect.
- **GUI:** A user-friendly interface built with Tkinter.
- **Multi-Client Support:** The server can handle multiple clients simultaneously (future feature).
- **File Sharing:** Users can send files securely (future feature).
- **Emojis and Chat Bubbles:** Modern chat interface with emojis and chat bubbles (future feature).
- **Themes:** Light and dark themes for the GUI (future feature).

---

## How to Run

### Prerequisites

- Python 3.x
- Required Python libraries: `pycryptodome`, `bcrypt`

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Jackmerritt42/encrypted-chat.git
   cd encrypted-chat