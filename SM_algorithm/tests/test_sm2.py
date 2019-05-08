from SM_algorithm.gmssl import sm2, func

kp = sm2.CryptSM2(public_key='', private_key='')

private_key = kp.get_random_d(16)
public_key = kp.get_pa(private_key)

print("\nprivate_key & public_key")
print("private_key:%s" % private_key)
print("public_key:%s" % public_key)


if __name__ == '__main__':

    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
    data = "Python测试".encode()

    print("\nencrypt & decrypt")
    enc_data = sm2_crypt.encrypt(data)
    print("enc_data:%s" % enc_data)
    dec_data = sm2_crypt.decrypt(enc_data)
    print("dec_data:%s" % dec_data.decode())
    assert data == dec_data

    print("\nsign & verify")
    random_hex_str = func.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(data, random_hex_str)
    print('sign:%s' % sign)
    verify = sm2_crypt.verify(sign, data)
    print('verify:%s' % verify)
    assert verify
