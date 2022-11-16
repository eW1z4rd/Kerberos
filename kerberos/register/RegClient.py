import socket

from conf.config import SIGN
from lib.gmssl import sm2


class RegClient(object):
    def __init__(self, user, pwd):
        self.target_host = '127.0.0.1'
        self.target_port = 9002

        self.public_key = None

        self.user = user.encode()
        self.pwd = pwd.encode()

        self.register()

    def register(self):
        user_info = self.user + SIGN + self.pwd

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((self.target_host, self.target_port))

        self.public_key = client.recv(1024).decode()
        # print(self.public_key)

        sm2_crypt = sm2.CryptSM2(public_key=self.public_key, private_key='')
        enc_data = sm2_crypt.encrypt(user_info)

        client.send(enc_data)
        response = client.recv(1024)
        print(response.decode())

        client.close()


if __name__ == '__main__':
    # RegClient('KerberosUser', '这是A的密码111')
    RegClient('KerberosResource', '这是B的密码222')
