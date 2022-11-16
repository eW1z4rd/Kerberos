import pymysql

from conf.config import DB_HOST, DB_PORT, DB_USER, DB_PASSWD, DB_NAME


class KDCdb(object):
    def __init__(self):
        self.host = DB_HOST
        self.port = DB_PORT
        self.user = DB_USER
        self.password = DB_PASSWD
        self.database = DB_NAME
        self.charset = 'utf8'

    def connect_kdc_db(self):
        try:
            return pymysql.connect(host=self.host, port=self.port, user=self.user, password=self.password,
                                   database=self.database, charset=self.charset)
        except (ConnectionRefusedError, pymysql.err.OperationalError):
            print('Connect operation error')
            return False

    def create_table(self, sql):
        if self.connect_kdc_db():
            conn = self.connect_kdc_db()
            cursor = conn.cursor()
            try:
                cursor.execute(sql)
                return True
            except (pymysql.err.OperationalError, pymysql.err.InternalError):
                print('Create operation error - Table already exists')
            finally:
                cursor.close()
                conn.close()
        else:
            return False

    def insert_data(self, user, pwd, tb_name):
        if self.connect_kdc_db():
            conn = self.connect_kdc_db()
            cursor = conn.cursor()

            try:
                if tb_name == 'kdc_user':
                    cursor.execute(f'INSERT INTO kdc_user (u_name, pwd) VALUES (%s, %s)', (user, pwd))
                elif tb_name == 'kdc_login':
                    cursor.execute(f'INSERT INTO kdc_login (u_name, last_time) VALUES (%s, %s)', (user, pwd))
                conn.commit()
            except pymysql.err.IntegrityError:
                conn.rollback()
                print('Insert operation error - Duplicate entry')
            except pymysql.err.DataError:
                conn.rollback()
                print('Insert operation error - Data too long')
            else:
                print(f'[+] Insert {tb_name} success')
            finally:
                cursor.close()
                conn.close()
        else:
            return False

    def query_data(self, user, tb_name):
        if self.connect_kdc_db():
            conn = self.connect_kdc_db()
            cursor = conn.cursor()

            try:
                if tb_name == 'kdc_user':
                    cursor.execute(f'SELECT pwd FROM kdc_user WHERE u_name=%s', user)
                elif tb_name == 'kdc_login':
                    cursor.execute(f'SELECT last_time FROM kdc_login WHERE u_name=%s ORDER BY id DESC', user)
                return cursor.fetchone()
            except pymysql.err.InternalError:
                print('Query operation error - Unknown column')
            finally:
                cursor.close()
                conn.close()
        else:
            return False

    def delete_data(self, user):
        if self.connect_kdc_db():
            conn = self.connect_kdc_db()
            cursor = conn.cursor()

            try:
                cursor.execute(f'DELETE FROM kdc_user where u_name=%s', user)
                conn.commit()
            except pymysql.err.OperationalError:
                conn.rollback()
                print('Delete operation error')
            else:
                print('[+] Delete success')
            finally:
                cursor.close()
                conn.close()
        else:
            return False
