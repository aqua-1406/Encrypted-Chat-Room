import tkinter as tk
from tkinter import scrolledtext, filedialog
import socket
import threading
import rsa
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# RSA key generation
public, private = rsa.newkeys(1024)
public_partner = None
client = None

# AES key size
AES_KEY_SIZE = 16  # 128-bit key

# Function to encrypt file data using AES
def encrypt_file_aes(file_data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(file_data, AES.block_size))
    return cipher.iv + ct_bytes  # Prepend IV to the ciphertext

# Function to decrypt file data using AES
def decrypt_file_aes(encrypted_data, aes_key):
    iv = encrypted_data[:AES.block_size]
    ct = encrypted_data[AES.block_size:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Function to send a message
def send_message():
    message = msg_entry.get()
    if message and client:
        client.send(rsa.encrypt(message.encode(), public_partner))
        chat_window.config(state=tk.NORMAL)
        chat_window.insert(tk.END, "You: " + message + "\n")
        chat_window.config(state=tk.DISABLED)
        msg_entry.delete(0, tk.END)

# Function to send a file
def send_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            file_data = file.read()

            # Generate AES key and encrypt the file data
            aes_key = get_random_bytes(AES_KEY_SIZE)
            encrypted_file_data = encrypt_file_aes(file_data, aes_key)

            # Encrypt the AES key with RSA
            encrypted_aes_key = rsa.encrypt(aes_key, public_partner)

            # Send a "file" command, followed by the encrypted AES key and file data
            client.send(b"file")
            client.send(encrypted_aes_key)  # Send AES key encrypted with RSA
            client.send(encrypted_file_data)  # Send encrypted file data

            chat_window.config(state=tk.NORMAL)
            chat_window.insert(tk.END, f"You sent a file: {os.path.basename(file_path)}\n")
            chat_window.config(state=tk.DISABLED)

# Function to receive messages or files
def receive_messages():
    while True:
        try:
            # Check for commands (like "file")
            command = client.recv(1024)
            if command == b"file":
                encrypted_aes_key = client.recv(256)  # Adjust size based on RSA key size
                aes_key = rsa.decrypt(encrypted_aes_key, private)

                encrypted_file_data = client.recv(4096)  # Adjust size for larger files
                file_data = decrypt_file_aes(encrypted_file_data, aes_key)

                # Save the received file
                with open("received_file.pdf", 'wb') as file:
                    file.write(file_data)
                
                chat_window.config(state=tk.NORMAL)
                chat_window.insert(tk.END, "Partner sent a file: received_file.pdf\n")
                chat_window.config(state=tk.DISABLED)
            else:
                # Normal message
                message = rsa.decrypt(command, private).decode()
                chat_window.config(state=tk.NORMAL)
                chat_window.insert(tk.END, "Partner: " + message + "\n")
                chat_window.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Error: {e}")
            break

# Function to handle connection
def handle_connection():
    global public_partner, client

    choice = var.get()
    if choice == 1:  # Host
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("ip address", port number))  # Bind to localhost for local testing
        server.listen()
        client, _ = server.accept()
        client.send(public.save_pkcs1("PEM"))
        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
    elif choice == 2:  # Connect
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("ip address", port number))  # Connect to localhost for local testing
        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
        client.send(public.save_pkcs1("PEM"))

    # Start the thread for receiving messages
    threading.Thread(target=receive_messages, daemon=True).start()

# Function to start the connection process
def start_connection():
    threading.Thread(target=handle_connection, daemon=True).start()

# Tkinter GUI setup
root = tk.Tk()
root.title("Secure Chat Room")

# Connection selection
var = tk.IntVar()
host_radio = tk.Radiobutton(root, text="Host", variable=var, value=1)
connect_radio = tk.Radiobutton(root, text="Connect", variable=var, value=2)
host_radio.grid(column=0, row=0, padx=5, pady=5)
connect_radio.grid(column=1, row=0, padx=5, pady=5)

# Start connection button
start_button = tk.Button(root, text="Start", command=start_connection)
start_button.grid(column=2, row=0, padx=5, pady=5)

# Chat window
chat_window = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=20)
chat_window.grid(column=0, row=1, columnspan=3, padx=5, pady=5)
chat_window.config(state=tk.DISABLED)

# Message entry field
msg_entry = tk.Entry(root, width=40)
msg_entry.grid(column=0, row=2, padx=5, pady=5)

# Send button
send_button = tk.Button(root, text="Send", command=send_message)
send_button.grid(column=2, row=2, padx=5, pady=5)

# Add a "Send File" button
send_file_button = tk.Button(root, text="Send File", command=send_file)
send_file_button.grid(column=1, row=2, padx=5, pady=5)

root.mainloop()
