from lib.db import KDCdb


def create_table_user():
    sql = """CREATE TABLE kdc_user (
    id INT auto_increment PRIMARY KEY,
    u_name VARCHAR(20) NOT NULL UNIQUE,
    pwd VARCHAR(40) NOT NULL)"""

    return KDCdb().create_table(sql)


def create_table_login():
    sql = """CREATE TABLE kdc_login (
    id INT auto_increment PRIMARY KEY,
    u_name VARCHAR(20) NOT NULL,
    last_time VARCHAR(40) NOT NULL)"""

    return KDCdb().create_table(sql)


if __name__ == '__main__':
    if create_table_user() and create_table_login():
        print('[+] Create table success')
