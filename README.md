This is a Chat-Room which is based on the idea of Encrypted chat and file sharing spaces.
I have made a  python script that allows users to create a chat room between two users using the respective IP-Addresses of the users and then they can chat or share files with each other being in this space.
It uses **Python's RSA Module** to ammend the functionality of encryption anf decryption.

**RSA MODULE** :
This module works on the concept of Assymetric Encryption where we generate a Public Key and a Private Key for the sender and the reciever and then this public and private key are used at bothe the ends
to read the and provide the given information.

This helps us prevent the major Cyber-Security Threats like 
1. **Man-in-the-Middle Attack**
2. **Phishing**
3. **Data Tampering**

More libraries and modules used are:
1. **Socket** - For creating/establishing the Client - Server Connection 
2. **Threading** -  Multithreading allows the application to handle multiple tasks concurrently, While one thread handles encryption and decryption,
                    another can manage the user interface, allowing smooth scrolling and instant feedback to user inputs.
