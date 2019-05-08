from Database.OptDatabase import KDCdb
from random import choice, shuffle

Kdb = KDCdb()
last = Kdb.query_data("KerberosUser", "kdc_login")
format_last = last[0][:10]
fake_list = [format_last]

for i in range(4):

    while True:
        month = choice([str(x) for x in range(1, 13)])
        day = choice([str(x) for x in range(1, 31)])
        if month != '2' or (day != '29' and day != '30'):
            break

    fake_data = format_last[:4] + "-" + month.zfill(2) + "-" + day
    fake_list.append(fake_data)

shuffle(fake_list)

print(fake_list)
