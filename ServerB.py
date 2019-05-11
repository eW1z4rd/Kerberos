from SM_algorithm.gmssl import sm2, sm3, sm4
from func import *

from KerberosSocket import Socket


class ServerB(Socket):
    def __init__(self, pwd):
        super().__init__()

        self.bind_ip = "0.0.0.0"
        self.bind_port = 8001

        self.B_pwd = sm3.hash(pwd.encode())[:20]

        self.Ksrv = self.set_ksrv()
        self.crypt_sm4_ksrv = sm4.CryptSM4()

        self.Kclt_srv = None
        self.crypt_sm4_kclt_srv = sm4.CryptSM4()

        self.pri_key, self.pub_key_b = self.cl_pkc_init()

        self.nonces = []

    def set_ksrv(self):
        return sm3.hash(self.B_pwd)

    """ Third： UserA 和 ResourceB 互相认证 """

    @staticmethod
    def cl_pkc_init():
        kp = sm2.CryptSM2(public_key='', private_key='')

        b1 = kp.get_random_d(16)
        b2 = kp.get_pa(b1)

        return b1, b2

    def cl_pkc_cal(self, pub):
        kp = sm2.CryptSM2(public_key='', private_key='')
        return kp._kg(int(self.pri_key, 16), pub)

    def resolve_CS_REQ(self, cs_req):
        """ 解密 Ticket，解密 enc_data，对比 UserA，对比 timestamp, nonce, 完成密钥协商 """

        enc_data, Ticket, pub_key_a = cs_req.split(SIGN)

        ng_key = self.cl_pkc_cal(pub_key_a.decode())

        self.crypt_sm4_ksrv.set_key(self.Ksrv, sm4.SM4_DECRYPT)
        dec_ticket = self.crypt_sm4_ksrv.crypt_ecb(Ticket)

        UserA_1, self.Kclt_srv = dec_ticket[0:-16], dec_ticket[-16:]
        self.Kclt_srv += ng_key[:16].encode()

        self.crypt_sm4_kclt_srv.set_key(self.Kclt_srv, sm4.SM4_DECRYPT)
        dec_data = self.crypt_sm4_kclt_srv.crypt_ecb(enc_data)

        UserA_2, timestamp, nonce = dec_data.split(SIGN)

        tsp_compare(timestamp)
        nonce_compare(nonce, self.nonces)
        user_compare(UserA_1, UserA_2)

    def set_CS_REP(self, cs_req):
        """ CS_REP = { timestamp, nonce } Kclt-srv, pub_key_b """

        timestamp = set_timestamp()
        nonce = get_random_str(8)

        self.resolve_CS_REQ(cs_req)

        self.crypt_sm4_kclt_srv.set_key(self.Kclt_srv, sm4.SM4_ENCRYPT)
        CS_REP = self.crypt_sm4_kclt_srv.crypt_ecb(timestamp + SIGN + nonce) + \
                 SIGN + self.pub_key_b.encode()

        print('[+] Set CS_REP: ', CS_REP)

        return CS_REP

    def _handle_client(self, client_socket):
        CS_REQ = client_socket.recv(1024)
        print('[+] Received CS_REQ: ', CS_REQ)

        CS_REP = self.set_CS_REP(CS_REQ)
        client_socket.send(CS_REP)

        client_socket.close()

    def main(self):
        self.server('ServerB')


if __name__ == '__main__':
    # b = ServerB("这是B的密码222")

    pw = input("password: ")

    b = ServerB(pw)
    b.main()
