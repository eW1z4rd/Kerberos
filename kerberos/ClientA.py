import socket

from conf.config import SIGN
from lib.common import get_random_iv, set_timestamp, get_random_str, tsp_compare, nonce_compare
from lib.gmssl import sm2, sm3, sm4
from lib.ksocket import Socket


class ClientA(Socket):
    def __init__(self, user, pwd, resource):
        super().__init__()

        self.UserA = user.encode()
        self.A_pwd = sm3.hash(pwd.encode())[:20]
        self.ResourceB = resource.encode()

        self.Kclt = self.set_kclt()
        self.crypt_sm4_kclt = sm4.CryptSM4()

        self.Kclt_kdc = None
        self.crypt_sm4_kclt_kdc = sm4.CryptSM4()

        self.Kclt_srv = None
        self.crypt_sm4_kclt_srv = sm4.CryptSM4()

        self.pri_key = None

        self.nonces = []

    def set_kclt(self):
        return sm3.hash(self.A_pwd)

    """ First： UserA 和 KDC 互相认证 """

    def set_AS_REQ(self):
        """ AS_REQ = { timestamp } Kclt, UserA, nonce, iv """

        iv = get_random_iv()
        timestamp = set_timestamp()

        self.crypt_sm4_kclt.set_key(self.Kclt, sm4.SM4_ENCRYPT)
        enc_timestamp = self.crypt_sm4_kclt.crypt_cbc(iv, timestamp)

        nonce = get_random_str(10)

        AS_REQ = enc_timestamp + SIGN + self.UserA + nonce + iv
        print('[+] Set AS_REQ: ', AS_REQ)

        return AS_REQ

    @staticmethod
    def format_AS_REP(as_rep):
        """ 从 AS_REP 中分离出 TGT, { Kclt-kdc, timestamp, nonce } Kclt, iv """

        AS_REP_LIST = as_rep.split(SIGN)
        return [AS_REP_LIST[0], AS_REP_LIST[1][:-16], AS_REP_LIST[1][-16:]]

    def kclt_decrypt(self, enc, iv):
        """ 使用 Kclt 解密 { Kclt-kdc, timestamp, nonce } """

        self.crypt_sm4_kclt.set_key(self.Kclt, sm4.SM4_DECRYPT)
        dec_data = self.crypt_sm4_kclt.crypt_cbc(iv, enc)

        return [dec_data[:16], dec_data[16:-10]]

    def resolve_AS_REP(self, as_rep):
        """ 保存 TGT ，解密 enc_data，对比 timestamp """

        TGT, enc_data, iv = self.format_AS_REP(as_rep)
        self.Kclt_kdc, timestamp = self.kclt_decrypt(enc_data, iv)

        tsp_compare(timestamp)

        return TGT

    """ Second： UserA 请求 KDC 认证 ResourceB """

    def set_TGS_REQ(self, as_rep):
        """ TGS_REQ = TGT, { UserA, timestamp } Kclt-kdc, ResourceB """

        timestamp = set_timestamp()

        TGT = self.resolve_AS_REP(as_rep)

        self.crypt_sm4_kclt_kdc.set_key(self.Kclt_kdc, sm4.SM4_ENCRYPT)
        enc_data = self.crypt_sm4_kclt_kdc.crypt_ecb(self.UserA + SIGN + timestamp)

        TGS_REQ = TGT + SIGN + enc_data + SIGN + self.ResourceB
        print('[+] Set TGS_REQ: ', TGS_REQ)

        return TGS_REQ

    def resolve_TGS_REP(self, tgs_rep):
        """ 使用 Kclt-kdc 解密 { Kclt-srv }，保存 Ticket """

        enc_kclt_srv, Ticket = tgs_rep.split(SIGN)

        self.crypt_sm4_kclt_kdc.set_key(self.Kclt_kdc, sm4.SM4_DECRYPT)
        Kclt_srv = self.crypt_sm4_kclt_kdc.crypt_ecb(enc_kclt_srv)

        return Kclt_srv, Ticket

    """ Third： UserA 和 ResourceB 互相认证 """

    @staticmethod
    def cl_pkc_init():
        kp = sm2.CryptSM2(public_key='', private_key='')

        a1 = kp.get_random_d(16)
        a2 = kp.get_pa(a1)

        return a1, a2

    def cl_pkc_cal(self, pub):
        kp = sm2.CryptSM2(public_key='', private_key='')
        return kp._kg(int(self.pri_key, 16), pub)

    def set_CS_REQ(self, tgs_rep):
        """ CS_REQ = { UserA, timestamp, nonce } Kclt-srv, Ticket, pub_key_a """

        timestamp = set_timestamp()
        nonce = get_random_str(8)

        self.Kclt_srv, Ticket = self.resolve_TGS_REP(tgs_rep)

        self.crypt_sm4_kclt_kdc.set_key(self.Kclt_srv, sm4.SM4_ENCRYPT)
        enc_data = self.crypt_sm4_kclt_kdc.crypt_ecb(self.UserA + SIGN +
                                                     timestamp + SIGN + nonce)

        self.pri_key, pub_key_a = self.cl_pkc_init()

        CS_REQ = enc_data + SIGN + Ticket + SIGN + pub_key_a.encode()
        print('[+] Set CS_REQ: ', CS_REQ)

        return CS_REQ

    def resolve_CS_REP(self, cs_rep):
        """ 使用 Kclt-srv 解密 { timestamp, nonce }，保存 Ticket，完成密钥协商 """

        enc_data, pub_key_b = cs_rep.split(SIGN)

        ng_key = self.cl_pkc_cal(pub_key_b.decode())
        self.Kclt_srv += ng_key[:16].encode()

        self.crypt_sm4_kclt_srv.set_key(self.Kclt_srv, sm4.SM4_DECRYPT)
        dec_data = self.crypt_sm4_kclt_srv.crypt_ecb(enc_data)

        timestamp, nonce = dec_data.split(SIGN)

        tsp_compare(timestamp)
        nonce_compare(nonce, self.nonces)

    def client_KDC(self):
        self.target_host = '127.0.0.1'
        self.target_port = 9000

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((self.target_host, self.target_port))

        AS_REQ = self.set_AS_REQ()
        client.send(AS_REQ)

        query = client.recv(1024).decode()
        print('Candidate list:', query)
        data = input('Please select your last login time (yyyy-mm-dd): ').encode()
        client.send(sm3.hash(data))

        AS_REP = client.recv(1024)
        print('[+] Received AS_REP: ', AS_REP)

        TGS_REQ = self.set_TGS_REQ(AS_REP)
        client.send(TGS_REQ)

        TGS_REP = client.recv(1024)
        print('[+] Received TGS_REP: ', TGS_REP)

        return TGS_REP

    def client_ServerB(self, tgs_rep):
        self.target_host = '127.0.0.1'
        self.target_port = 9001

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((self.target_host, self.target_port))

        CS_REQ = self.set_CS_REQ(tgs_rep)
        client.send(CS_REQ)

        CS_REP = client.recv(1024)
        print('[+] Received CS_REP: ', CS_REP)

        self.resolve_CS_REP(CS_REP)

    def main(self):
        TGS_REP = self.client_KDC()
        self.client_ServerB(TGS_REP)


if __name__ == '__main__':
    ClientA('KerberosUser', '这是A的密码111', 'KerberosResource').main()
