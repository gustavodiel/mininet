#!/usr/bin/env python3

import socket
import time
import threading
import sys


class SenderThread():
    def __init__(self):
        super(SenderThread, self).__init__()
        self.ip = "<broadcast>"
        self.port = 17500
        self.message = "Hello, World!"

        i = 0

        self.listener = ListenThread()
        self.listener.start()

        while i < 50000:
            time.sleep(0.5)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.sendto(bytes('{} - {}'.format(self.message, i), "utf-8"), (self.ip, self.port))
            print("Sent")
            i = i + 1

        self.listener.join()


class ListenThread(threading.Thread):
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP
        server_address = ('0.0.0.0', 17500)

        sock.bind(server_address)
        sock.listen(1)
        while True:
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive the data in small chunks and retransmit it
                while True:
                    data = connection.recv(2048)
                    print('received "%s"' % data)
                    data = connection.recv(2048)
                    print('also received %s' % data)
                    print('Ending', client_address)
                    break
            finally:
                # Clean up the connection
                connection.close()


if __name__ == '__main__':
    sender = SenderThread()
