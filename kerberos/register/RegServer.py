import time

from conf.config import SIGN
from lib.db import KDCdb
from lib.gmssl import sm2, sm3
from lib.ksocket import Socket


class RegServer(Socket):
    def __init__(self):
        super().__init__()

        self.bind_ip = '0.0.0.0'
        self.bind_port = 9002

        self.private_key = None
        self.public_key = None

        self.Kdb = KDCdb()

    def generate_kp(self):
        kp = sm2.CryptSM2(public_key='', private_key='')

        self.private_key = kp.get_random_d()
        self.public_key = kp.get_pa(self.private_key)

    def _handle_client(self, client_socket):
        self.generate_kp()

        client_socket.send(self.public_key.encode())

        user_info = client_socket.recv(1024)
        print('[+] Received UserInfo: ', user_info)

        sm2_crypt = sm2.CryptSM2(public_key='', private_key=self.private_key)
        dec_data = sm2_crypt.decrypt(user_info)

        user, pwd = dec_data.split(SIGN)
        self.Kdb.insert_data(user.decode(), sm3.hash(pwd).decode()[:20], 'kdc_user')

        loc_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        self.Kdb.insert_data(user.decode(), loc_time, 'kdc_login')

        client_socket.send('[+] Register success'.encode())

        client_socket.close()

    def main(self):
        self.server('RegServer')


if __name__ == '__main__':
    RegServer().main()
