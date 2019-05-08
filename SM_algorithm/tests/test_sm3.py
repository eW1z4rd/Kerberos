from SM_algorithm.gmssl import sm3

if __name__ == '__main__':

    hash_data = sm3.hash("Python测试".encode())
    print(hash_data)
