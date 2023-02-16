# uft.py
# Joshua Lin
# CSC 574
# 9/13/21

import socket
import sys

# Size of data being sent or received
BUFFER_SIZE = 1024

if str(sys.argv[1]) == "-l":
    # Server

    # Empty message variable to use
    message = b''
    # Socket creation
    s = socket.socket()
    # Host on local computer
    host = 'localhost'
    # Port number from command line
    port = int(sys.argv[2])
    # Binding socket to port
    s.bind((host, port))
    # Listen for connections
    s.listen(5)
    # Accepting connection
    conn, addr = s.accept()

    # Receiving message from Client
    while True:
        data = conn.recv(BUFFER_SIZE)
        message += data

        if not data:
            break

    # Writing plain text to output file
    sys.stdout.buffer.write(message)

    # Closing connection
    conn.close()

else:
    # Client

    # Creating socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Host from command line
    host = sys.argv[1]
    # Port number from command line
    port = int(sys.argv[2])
    # Connecting to port
    s.connect((host, port))

    # Message to send from stdin
    message = sys.stdin.buffer.read()
    # Sending message to server
    s.sendall(message)

    # Closing connection
    s.close()
