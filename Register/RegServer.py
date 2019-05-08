import time

from Database.OptDatabase import KDCdb

from SM_algorithm.gmssl import sm2, sm3
from func import SIGN

from KerberosSocket import Socket


class RegServer(Socket):
    def __init__(self):
        super().__init__()

        self.bind_ip = "0.0.0.0"
        self.bind_port = 8002

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

        UserInfo = client_socket.recv(1024)
        print("[+] Received UserInfo: ", UserInfo)

        sm2_crypt = sm2.CryptSM2(public_key='', private_key=self.private_key)
        dec_data = sm2_crypt.decrypt(UserInfo)

        user, pwd = dec_data.split(SIGN)
        self.Kdb.insert_data(user.decode(), sm3.hash(pwd).decode()[:20], "kdc_tb")

        loc_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        self.Kdb.insert_data(user.decode(), loc_time, "kdc_login")

        client_socket.send("[+] Register Successfully!".encode())

        client_socket.close()

    def main(self):
        self.server('RegServer')


if __name__ == '__main__':
    RegServer().main()
