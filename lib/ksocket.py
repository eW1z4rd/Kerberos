# kerberos socket

import socket
import threading


class Socket(object):
    def __init__(self):
        self.bind_ip = '0.0.0.0'
        self.bind_port = 8000

        self.target_host = '127.0.0.1'
        self.target_port = 8000

    @staticmethod
    def _handle_client(client_socket: socket.socket):
        msg = 'HelloWorld'

        request = client_socket.recv(1024)

        print('[*] Received: %s' % request)

        client_socket.send(msg.encode())
        client_socket.close()

    def server(self, server_name):
        print('[*] %s Service is running... ' % server_name)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.bind_ip, self.bind_port))
        server.listen(5)
        while True:
            client, addr = server.accept()

            print('[*] Accepted connection from: %s:%d\n' % (addr[0], addr[1]))

            client_handler = threading.Thread(target=self._handle_client, args=(client,))
            client_handler.start()

    def client(self, msg):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((self.target_host, self.target_port))
        client.send(msg.encode())

        response = client.recv(1024)
        print(response)

        return response
