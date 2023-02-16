# eft-dh.py
# Joshua Lin
# CSC 574
# 9/13/21

import socket
import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

# Size of messages sent and received
BUFFER_SIZE = 1024
# Port number from command line
port = int(sys.argv[2])
# Creating socket
s = socket.socket()
# Diﬃe-Hellman values
g = 2
p = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

if str(sys.argv[1]) == "-l":
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

    # Server's b for D-H
    b = get_random_bytes(2 ^ 256)
    # Server's B for D-H
    publicB = pow(g, int.from_bytes(b, 'little'), p)
    # Sending B to Client
    conn.send(publicB.to_bytes(200, 'little'))

    # Receiving message from Client
    while True:
        data = conn.recv(BUFFER_SIZE)
        message += data

        if not data:
            break

    # Splitting received message by b'zdf/n'
    chunk = message.split(b'zdf/n')
    # A from Client for D-H
    publicA = int.from_bytes(chunk[0], 'little')
    # Salt from  Client for encrypted key
    salt = bytes(chunk[1])
    # IV from Client for encrypted key
    iv = bytes(chunk[2])
    # Tag for decrypting message
    tag = bytes(chunk[3])
    # Encrypted message from Client
    data = bytes(chunk[4])
    # Computing Secret Key using D-H
    secretKey = pow(publicA, int.from_bytes(b, 'little'), p)
    # Computing encrypted key used to decrypt message
    key = PBKDF2(secretKey.to_bytes(200, 'little'), salt, 16, count=1000000, hmac_hash_module=SHA256)
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
    host = sys.argv[1]
    # Connecting to port
    s.connect((host, port))

    # Receiving Server's B
    publicBbyte = s.recv(BUFFER_SIZE)
    publicB = int.from_bytes(publicBbyte, 'little')

    # Client's a for D-H
    a = get_random_bytes(2 ^ 256)
    # Client's A for D-H
    publicA = pow(g, int.from_bytes(a, 'little'), p)
    # Secret key computed from Server's B, Client's a, and p
    secretKey = pow(publicB, int.from_bytes(a, 'little'), p)

    # Message to send from stdin
    message = sys.stdin.buffer.read()
    # Salt for key
    salt = get_random_bytes(16)
    # Computing key for encryption
    key = PBKDF2(secretKey.to_bytes(200, 'little'), salt, 16, count=1000000, hmac_hash_module=SHA256)
    # Cipher for encryption
    cipher = AES.new(key, AES.MODE_GCM)
    # IV to send to Server
    iv = cipher.nonce
    # Encrypted message and tag
    ciphertext, tag = cipher.encrypt_and_digest(message)
    # Encrypted message + other info
    ciphertext = b'zdf/n' + salt + b'zdf/n' + iv + b'zdf/n' + tag + b'zdf/n' + ciphertext
    # Sending all data
    s.send(publicA.to_bytes(200, 'little'))
    s.sendall(ciphertext)

    # Closing connection
    s.close()
