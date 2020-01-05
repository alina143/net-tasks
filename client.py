import socket
from threading import Thread
import ssl


def disconnect(sock, login):
    print("closed")
    print(login)
    sock.send(bytes(login, 'utf8'))
    sock.close()
    exit(0)
    pass


def reciveMessage(sock, message):
    while True:
        message = sock.recv(1000)
        print(message.decode())


serverAddress = ('192.168.43.249', 8017)

while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)##client socket
    connstream = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH-AES256-SHA")##wrap socket created
    ##context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)##context manager for creating context objects
    ##connstream = context.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH-AES256-SHA")  ## create wrapped socket encrypted
    connstream.connect(serverAddress)

    print("Enter login:")
    login = input()
    print("Enter password")
    passwd = input()
    auth = login + '~' + passwd
    connstream.send(bytes(auth, 'utf8'))
    data = connstream.recv(1000)
    if data.decode('utf8') == 'correct':
        print('Correct!')
        break
    else:
        connstream.close()
        print('Incorrect login or password. Try again!')
try:
    recvThread = Thread(target=reciveMessage, args=(connstream, 'hello'))
    recvThread.start()

    while True:
        message = input()
        if message == "!disconnect":
            connstream.send(bytes(message, 'utf8'))
            disconnect(connstream, login)
        connstream.send(bytes(message, 'utf8'))

except KeyboardInterrupt:
    disconnect(connstream)

connstream.close()