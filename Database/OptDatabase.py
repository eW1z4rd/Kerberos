import logging
import pymysql


class KDCdb(object):
    def __init__(self):
        self.host = '127.0.0.1'
        self.user = 'username'
        self.password = 'yourpwd'
        self.database = 'dbname'
        self.charset = 'utf8'

    def connect_kdc_db(self):
        try:
            return pymysql.connect(host=self.host, user=self.user,
                                   password=self.password, database=self.database,
                                   charset=self.charset)
        except (ConnectionRefusedError, pymysql.err.OperationalError):
            logging.error('Connect operation error')
            return False

    def create_table_tb(self):
        if self.connect_kdc_db():
            conn = self.connect_kdc_db()
            cursor = conn.cursor()
            try:
                sql = """CREATE TABLE kdc_tb (
                id INT auto_increment PRIMARY KEY,
                u_name VARCHAR(20) NOT NULL UNIQUE,
                pwd VARCHAR(40) NOT NULL);"""

                cursor.execute(sql)

            except (pymysql.err.OperationalError, pymysql.err.InternalError):
                logging.error('Create operation error - Table already exists')

            finally:
                cursor.close()
                conn.close()
        else:
            return 0

    def create_table_lg(self):
        if self.connect_kdc_db():
            conn = self.connect_kdc_db()
            cursor = conn.cursor()
            try:
                sql = """CREATE TABLE kdc_login (
                id INT auto_increment PRIMARY KEY,
                u_name VARCHAR(20) NOT NULL,
                pwd VARCHAR(40) NOT NULL);"""

                cursor.execute(sql)

            except (pymysql.err.OperationalError, pymysql.err.InternalError):
                logging.error('Create operation error - Table already exists')

            finally:
                cursor.close()
                conn.close()
        else:
            return 0

    def insert_data(self, user, pwd, tb_name):
        if self.connect_kdc_db():
            conn = self.connect_kdc_db()
            cursor = conn.cursor()

            try:
                sql = "INSERT INTO " + tb_name + " (u_name, pwd) VALUES ('%s', '%s')" % (user, pwd)

                cursor.execute(sql)
                conn.commit()

            except pymysql.err.IntegrityError:
                conn.rollback()
                logging.error('Insert operation error - Duplicate entry')

            except pymysql.err.DataError:
                conn.rollback()
                logging.error('Insert operation error - Data too long')

            else:
                print('[+] Insert success')

            finally:
                cursor.close()
                conn.close()
        else:
            return 0

    def query_data(self, user, tb_name):
        if self.connect_kdc_db():
            conn = self.connect_kdc_db()
            cursor = conn.cursor()

            try:
                sql = "SELECT pwd FROM " + tb_name + " where u_name = '%s'" % user

                cursor.execute(sql)
                pwd = cursor.fetchall()[-1]  # 选择最近插入的数据

                return pwd

            except pymysql.err.InternalError:
                logging.error('Query operation error - Unknown column')

            finally:
                cursor.close()
                conn.close()

        else:
            return 0

    def delete_data(self, user):
        if self.connect_kdc_db():
            conn = self.connect_kdc_db()
            cursor = conn.cursor()

            try:
                sql = "DELETE FROM kdc_tb where u_name = '%s'" % user

                cursor.execute(sql)
                conn.commit()

            except pymysql.err.OperationalError:
                conn.rollback()
                logging.exception('Delete operation error')

            else:
                print('[+] Delete success')

            finally:
                cursor.close()
                conn.close()
        else:
            return 0


if __name__ == '__main__':
    kdb = KDCdb()
    kdb.create_table_lg()
