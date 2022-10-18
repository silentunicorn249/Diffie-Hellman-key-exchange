from socket import *
from random import randint
from ciphers import caeser

primes = [13457, 13463, 13469, 13477, 13487, 13499, 13513, 13523,
          13537, 13553, 13567, 13577, 13591, 13597, 13613, 13619,
          13627, 13633, 13649, 13669, 13679, 13681, 13687, 13691,
          13693, 13697, 13709, 13711, 13721, 13723, 13729, 13751,
          13757, 13759, 13763, 13781, 13789, 13799, 13807, 13829,
          13831, 13841, 13859, 13873, 13877, 13879, 13883, 13901,
          13903, 13907, 13913, 13921, 13931, 13933, 13963, 13967,
          13997, 13999, 14009, 14011, 14029, 14033, 14051, 14057,
          14071, 14081, 14083, 14087, 14107, 14143, 14149]

with socket(AF_INET, SOCK_STREAM) as s:
    try:
        print("Choosing a private key...")
        pvt = primes[randint(1, len(primes) - 1)]

        print("Connecting to remote...")
        s.connect(("127.0.0.1", 2046))
        print("Connected!!!\n")

        print("Getting public keys...")
        keys = s.recv(1024).decode()
        base, mod, serverKey = [int(i) for i in keys.split()]
        print(f"Received base: {base}")
        print(f"Received mod: {mod}")
        print(f"Received serverKey: {serverKey}")

        clientKey = base ** pvt % mod
        print(f"Generated clientLey: {clientKey}\n")

        print("Sending clientKey...")
        s.send(str(clientKey).encode())

        key = serverKey**pvt % mod
        print(f"Generated symmetric key {key}")

        ciphered = s.recv(1024).decode()
        print(f"Got ciphered message: {ciphered}")
        message = caeser(ciphered, -(key%25 +1))
        print(f"Message: {message}")


    except Exception as e:
        print(e)

