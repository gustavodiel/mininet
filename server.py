#!/usr/bin/env python3

import socket
import sys


class ReceiverThread():
    def __init__(self):
        super(ReceiverThread, self).__init__()
        self.port = 17500

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.port))
        while True:
            data, server = sock.recvfrom(2024)
            print("Received: " + str(data))
            self.makeConnection(data, server)

    def makeConnection(self, msg, server):
        try:
            anotherSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ip, _ = server
            port = 17500
            print("connecting to", (ip, port))
            anotherSock.connect((ip, port))
            print('sending "%s"' % str(msg))
            anotherSock.sendall(msg)
            anotherSock.sendall(bytes('Finished :3', 'utf-8'))
            anotherSock.close()
        except:
            print("Error!")


if __name__ == '__main__':
    receiver = ReceiverThread()

