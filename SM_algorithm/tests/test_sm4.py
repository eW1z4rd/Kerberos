from SM_algorithm.gmssl import sm4


if __name__ == '__main__':

    value = 'Python测试Python测试Python测试'.encode()
    crypt_sm4 = sm4.CryptSM4()
    key = crypt_sm4.get_random_key()
    iv = crypt_sm4.get_random_iv()
    print(iv.decode())
    print(key.decode())

    print("\nECB encrypt & decrypt")
    crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_ecb(value)
    print(encrypt_value)
    crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)
    print(decrypt_value.decode())
    assert value == decrypt_value

    print("\nCBC encrypt & decrypt")
    crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_cbc(iv, value)
    print(encrypt_value)
    crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_cbc(iv, encrypt_value)
    print(decrypt_value.decode())
    assert value == decrypt_value
