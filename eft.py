# eft.py
# Joshua Lin
# CSC 574
# 9/13/21

import socket
import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

# Size of data being sent or received
BUFFER_SIZE = 1024
# Key from command line
keyIn = sys.argv[2]
# Port number from command line
port = int(sys.argv[4])
# Socket creation
s = socket.socket()

if str(sys.argv[3]) == "-l":
    #  Server
    host = 'localhost'
    # Binding socket to port
    s.bind((host, port))
    # Listen for connections
    s.listen(5)
    # Accepting connection
    conn, addr = s.accept()

    # Empty message variable to use
    message = b''

    # Receiving message from Client
    while True:
        data = conn.recv(BUFFER_SIZE)
        message += data

        if not data:
            break

    # Splitting received message by b'zdf/n'
    chunk = message.split(b'zdf/n')

    # Salt from  Client for encrypted key
    salt = bytes(chunk[0])
    # IV from Client for encrypted key
    iv = bytes(chunk[1])
    # Tag for decrypting message
    tag = bytes(chunk[2])
    # Encrypted message from Client
    data = bytes(chunk[3])
    # Computing encrypted key used to decrypt message
    key = PBKDF2(keyIn, salt, 16, count=1000000, hmac_hash_module=SHA256)
    # Cipher to decrypt message
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    # Decrypting message
    try:
        decryptMessage = cipher.decrypt_and_verify(data, tag)
        # Writing plain text to output file
        sys.stdout.buffer.write(decryptMessage)
    except ValueError:
        # Values do not match up somewhere
        sys.stderr.write("Error: integrity check failed.")
        exit(0)

    # Closing connection
    conn.close()

else:
    #  Client

    # Host from command line
    host = sys.argv[3]
    # Connecting to port
    s.connect((host, port))
    # Message to send from stdin
    message = sys.stdin.buffer.read()
    # Salt for key
    salt = get_random_bytes(16)
    # Computing key for encryption
    key = PBKDF2(keyIn, salt, 16, count=1000000, hmac_hash_module=SHA256)
    # Cipher for encryption
    cipher = AES.new(key, AES.MODE_GCM)
    # IV to send to Server
    iv = cipher.nonce
    # Encrypted message and tag
    ciphertext, tag = cipher.encrypt_and_digest(message)
    # Encrypted message + other info
    ciphertext = salt + b'zdf/n' + iv + b'zdf/n' + tag + b'zdf/n' + ciphertext

    # Sending all data
    s.sendall(ciphertext)

    # Closing connection
    s.close()
