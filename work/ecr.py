#using rsa to encrypt and decrypt and sender and reciever ends using private and public key. It is asssymteric as we use two different keys to encryot and decrypt messaages

import socket
import threading

import rsa

public, private = rsa.newkeys(1024)
public_partner = None

choice = input("Do you want to be a Host ? (1) or establish a Connection (2) :")

if choice == '1':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind (("", 9999))
    server.listen()

    client, _ = server.accept() 
    client.send(public.save_pkcs1("PEM"))
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))

elif choice == '2':
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("", 9999))

    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(public.save_pkcs1("PEM"))


else:
    exit()

def sending_message(c):
    while True:
        message = input("")
        c.send(rsa.encrypt(message.encode(), public_partner))
        print("You : " + message)

def recieving_message(c):
    while True:
        print("Partner : " + rsa.decrypt(c.recv(1024), private).decode())



threading.Thread(target = sending_message, args=(client,)).start()
threading.Thread(target= recieving_message,args=(client,)).start()


