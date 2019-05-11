from Database.OptDatabase import KDCdb
from SM_algorithm.gmssl import sm3, sm4
from func import *

from random import choice, shuffle

from KerberosSocket import Socket


class KDC(Socket):
    def __init__(self):
        super().__init__()

        self.bind_ip = "0.0.0.0"
        self.bind_port = 8000

        self.UserA = None
        self.A_pwd = None
        self.B_pwd = None

        self.Kclt = None
        self.crypt_sm4_kclt = sm4.CryptSM4()

        self.KDC_pwd = "kad8cm1p0ins0s3w1o9r2d".encode()
        self.Kkdc = self.set_kkdc()
        self.crypt_sm4_kkdc = sm4.CryptSM4()

        self.Kclt_kdc = None
        self.crypt_sm4_kclt_kdc = sm4.CryptSM4()

        self.Kdb = KDCdb()
        self.format_last = ''

    def set_kclt(self):
        return sm3.hash(self.A_pwd)

    def set_kkdc(self):
        return sm3.hash(self.KDC_pwd)

    def set_ksrv(self):
        return sm3.hash(self.B_pwd)

    @staticmethod
    def set_kclt_kdc():
        return get_random_str(16)

    @staticmethod
    def set_kclt_srv():
        return get_random_str(16)

    """ First： UserA 和 KDC 互相认证 """

    def format_AS_REQ(self, as_req):
        """ 从 AS_REQ 中分离出 { timestamp } Kclt, UserA, nonce, iv """

        AS_REQ_LIST = as_req.split(SIGN)
        return [AS_REQ_LIST[0], AS_REQ_LIST[1][:-26], AS_REQ_LIST[1][-16:]]

    def kclt_decrypt(self, enc, iv):
        """ 使用 Kclt 解密 { timestamp } """

        self.crypt_sm4_kclt.set_key(self.Kclt, sm4.SM4_DECRYPT)
        return self.crypt_sm4_kclt.crypt_cbc(iv, enc)

    def resolve_AS_REQ(self, as_req):
        """ 获取 UserA，解密 enc_timestamp，对比 timestamp, 记录 UserA 登陆信息 """

        enc_timestamp, self.UserA, iv = self.format_AS_REQ(as_req)

        self.A_pwd = self.Kdb.query_data(self.UserA.decode(), "kdc_tb")[0].encode()
        self.Kclt = self.set_kclt()

        timestamp = self.kclt_decrypt(enc_timestamp, iv)
        tsp_compare(timestamp)

    def query_last_login(self):
        """ 请求上次访问时间 """

        last_login = self.Kdb.query_data(self.UserA.decode(), "kdc_login")
        self.format_last = last_login[0][:10]

        fake_list = [self.format_last]

        for i in range(4):

            while True:
                month = choice([str(x) for x in range(1, 13)])
                day = choice([str(x) for x in range(1, 31)])
                if (month != '2' or (day != '29' and day != '30')) \
                        and int(month) <= int(self.format_last[5:7]) \
                        and int(day) < int(self.format_last[-2:]):
                    break

            fake_data = self.format_last[:4] + "-" + month.zfill(2) + "-" + day.zfill(2)
            fake_list.append(fake_data)

        shuffle(fake_list)
        return str(fake_list)

    def login_check(self, login):
        """ 比对上次登陆时间 """

        if login == sm3.hash(self.format_last.encode()):
            loc_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            self.Kdb.insert_data(self.UserA.decode(), loc_time, "kdc_login")
        else:
            print(R + "[-] KDC_ERR_LOGIN_INVALID" + w)
            os._exit(0)

    def kkdc_encrypt(self):
        """ TGT = { UserA, Kclt-kdc } Kkdc """

        self.crypt_sm4_kkdc.set_key(self.Kkdc, sm4.SM4_ENCRYPT)
        return self.crypt_sm4_kkdc.crypt_ecb(self.Kclt_kdc + self.UserA)

    def set_AS_REP(self, as_req):
        """ AS_REP = TGT, { Kclt-kdc, timestamp, nonce } Kclt, iv """

        self.resolve_AS_REQ(as_req)

        iv = get_random_iv()
        timestamp = set_timestamp()
        nonce = get_random_str(10)

        self.Kclt_kdc = self.set_kclt_kdc()

        self.crypt_sm4_kclt.set_key(self.Kclt, sm4.SM4_ENCRYPT)
        enc_data = self.crypt_sm4_kclt.crypt_cbc(iv, self.Kclt_kdc + timestamp + nonce)

        TGT = self.kkdc_encrypt()
        print('[+] TGT: ', TGT)

        AS_REP = TGT + SIGN + enc_data + iv
        print('[+] Set AS_REP: ', AS_REP)

        return AS_REP

    """ Second： UserA 请求 KDC 认证 ResourceB """

    @staticmethod
    def format_TGS_REQ(tgs_req):
        """ 从 TGS_REQ 中分离出 TGT, { UserA, timestamp } Kclt-kdc, ResourceB """

        TGS_REQ_LIST = tgs_req.split(SIGN)
        return [TGS_REQ_LIST[0], TGS_REQ_LIST[1], TGS_REQ_LIST[2]]

    def kkdc_decrypt(self, enc):
        """ 使用 Kkdc 解密 TGT """

        self.crypt_sm4_kkdc.set_key(self.Kkdc, sm4.SM4_DECRYPT)
        dec_data = self.crypt_sm4_kkdc.crypt_ecb(enc)

        return [dec_data[:16], dec_data[16:]]

    def kclt_kdc_decrypt(self, key, enc):
        """ 使用 Kclt-kdc 解密 { UserA, timestamp } """

        self.crypt_sm4_kclt_kdc.set_key(key, sm4.SM4_DECRYPT)
        dec_data = self.crypt_sm4_kclt_kdc.crypt_ecb(enc)

        dec_list = dec_data.split(SIGN)

        return [dec_list[0], dec_list[1]]

    def resolve_TGS_REQ(self, tgs_req):
        """ 解密 TGT，解密 enc_data，对比 UserA，对比 timestamp，保存 ResourceB """

        TGT, enc_data, ResourceB = self.format_TGS_REQ(tgs_req)
        Kclt_kdc, UserA_1 = self.kkdc_decrypt(TGT)
        UserA_2, timestamp = self.kclt_kdc_decrypt(Kclt_kdc, enc_data)

        tsp_compare(timestamp)
        user_compare(UserA_1, UserA_2)

        self.B_pwd = self.Kdb.query_data(ResourceB.decode(), "kdc_tb")[0].encode()

    def set_Ticket(self, kclt_srv):
        """ Ticket = { UserA, Kclt-srv } Ksrv """

        Ksrv = self.set_ksrv()

        crypt_sm4_ksrv = sm4.CryptSM4()
        crypt_sm4_ksrv.set_key(Ksrv, sm4.SM4_ENCRYPT)

        return crypt_sm4_ksrv.crypt_ecb(self.UserA + kclt_srv)

    def set_TGS_REP(self, tgs_req):
        """ TGS_REP = { Kclt-srv } Kclt-kdc, Ticket """

        self.resolve_TGS_REQ(tgs_req)

        Kclt_srv = self.set_kclt_srv()

        self.crypt_sm4_kclt_kdc.set_key(self.Kclt_kdc, sm4.SM4_ENCRYPT)
        enc_kclt_srv = self.crypt_sm4_kclt_kdc.crypt_ecb(Kclt_srv)

        Ticket = self.set_Ticket(Kclt_srv)
        print('[+] Ticket: ', Ticket)

        TGS_REP = enc_kclt_srv + SIGN + Ticket
        print('[+] Set TGS_REP: ', TGS_REP)

        return TGS_REP

    def _handle_client(self, client_socket):

        AS_REQ = client_socket.recv(1024)
        print('[+] Received AS_REQ: ', AS_REQ)

        AS_REP = self.set_AS_REP(AS_REQ)

        client_socket.send(self.query_last_login().encode())
        user_choice = client_socket.recv(1024)
        self.login_check(user_choice)

        client_socket.send(AS_REP)

        TGS_REQ = client_socket.recv(1024)
        print('[+] Received TGS_REQ: ', TGS_REQ)

        TGS_REP = self.set_TGS_REP(TGS_REQ)
        client_socket.send(TGS_REP)

        client_socket.close()

    def main(self):
        self.server('KDC')


if __name__ == '__main__':
    k = KDC()
    k.main()
