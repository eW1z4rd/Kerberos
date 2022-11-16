import os
import string
import time
from random import choice

from lib.pbkdf2 import re_gen_key


R = '\033[1;31m'
w = '\033[0m'


def set_timestamp():
    return str(time.time()).encode()


def tsp_compare(time_begin):
    time_end = set_timestamp()
    sub = float(time_end) - float(time_begin)  # 60s
    if sub <= 60:
        pass
    else:
        print(R + '[-] KDC_ERR_TIME_INVALID' + w)
        os._exit(0)


def nonce_compare(nonce, nonces):
    if nonce in nonces:
        print(R + '[-] KDC_ERR_NONCE_INVALID' + w)
        os._exit(0)
    else:
        nonces.append(nonce)


def user_compare(u1, u2):
    if u1 == u2:
        pass
    else:
        print(R + '[-] KDC_ERR_USER_INVALID' + w)
        os._exit(0)


def get_random_str(strlen=16):
    s = ''
    for i in range(strlen):
        a = choice(list(string.ascii_letters + string.digits))
        s = '%s%s' % (s, a)
        return re_gen_key(s, strlen).encode()


def get_random_iv(strlen=16):
    letterlist = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    s = ''
    for i in range(strlen):
        a = choice(letterlist)
        s = '%s%s' % (s, a)
    return s.encode()


def r_file(f_name):
    try:
        with open(f_name, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(R + '[-] No such file or directory' + w)


def w_file(f_name, s):
    with open(f_name, 'w') as f:
        f.write(s)
