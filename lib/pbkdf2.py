import hmac
import struct
import hashlib

from binascii import hexlify, unhexlify


def pbkdf2(password, salt, iters, keylen, digestmod=hashlib.sha1):
    """Run the PBKDF2 (Password-Based Key Derivation Function 2) algorithm
    and return the derived key. The arguments are:
    password (bytes or bytearray) -- the input password
    salt (bytes or bytearray) -- a cryptographic salt
    iters (int) -- number of iterations
    keylen (int) -- length of key to derive
    digestmod -- a cryptographic hash function: either a module
    supporting PEP 247, a hashlib constructor, or (in Python 3.4
    or later) the name of a hash function.
    """
    h = hmac.new(password, digestmod=digestmod)

    def prf(data):
        hm = h.copy()
        hm.update(data)
        return bytearray(hm.digest())

    key = bytearray()
    i = 1
    while len(key) < keylen:
        t = u = prf(salt + struct.pack('>i', i))
        for _ in range(iters - 1):
            u = prf(u)
            t = bytearray(x ^ y for x, y in zip(t, u))
        key += t
        i += 1
    return key[:keylen]


def re_gen_key(pwd, key_len):
    password = pwd.encode()
    salt = unhexlify(b'1234567878563412')
    return hexlify(pbkdf2(password, salt, 500, int(key_len/2), hashlib.sha256)).decode()


if __name__ == '__main__':
    print(re_gen_key('Python测试', 16))
