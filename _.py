from random import choice, shuffle

format_last = '2019-05-10'
fake_list = [format_last]


for i in range(4):

    while True:
        month = choice([str(x) for x in range(1, 13)])
        day = choice([str(x) for x in range(1, 31)])
        if (month != '2' or (day != '29' and day != '30')) \
                and int(month) <= int(format_last[5:7]) \
                and int(day) < int(format_last[-2:]):
            break

    fake_data = format_last[:4] + "-" + month.zfill(2) + "-" + day.zfill(2)
    fake_list.append(fake_data)

shuffle(fake_list)
print(fake_list)
