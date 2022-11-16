from lib.gmssl import sm2

kp = sm2.CryptSM2(public_key='', private_key='')

a1 = kp.get_random_d(16)
a2 = kp.get_pa(a1)

b1 = kp.get_random_d(16)
b2 = kp.get_pa(b1)
print(b2)

k1 = kp._kg(int(a1, 16), b2)
k2 = kp._kg(int(b1, 16), a2)

assert k1 == k2
