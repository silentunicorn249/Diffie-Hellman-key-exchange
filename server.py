from socket import *
from ciphers import caeser
from random import randint

primes = [13457, 13463, 13469, 13477, 13487, 13499, 13513, 13523,
          13537, 13553, 13567, 13577, 13591, 13597, 13613, 13619,
          13627, 13633, 13649, 13669, 13679, 13681, 13687, 13691,
          13693, 13697, 13709, 13711, 13721, 13723, 13729, 13751,
          13757, 13759, 13763, 13781, 13789, 13799, 13807, 13829,
          13831, 13841, 13859, 13873, 13877, 13879, 13883, 13901,
          13903, 13907, 13913, 13921, 13931, 13933, 13963, 13967,
          13997, 13999, 14009, 14011, 14029, 14033, 14051, 14057,
          14071, 14081, 14083, 14087, 14107, 14143, 14149]

message = "Hello there!!"

with socket(AF_INET, SOCK_STREAM) as s:
    try:
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 2046))
        s.listen()
        s.settimeout(0.5)  # setting timeout so windows can detect KeyboardInterrupt Error
        print("Socket created successfully!!!\n")
        print("Choosing a private key...")

        values = []
        pvt = primes[randint(1,len(primes) - 1)]
        values.append(pvt)
        print(f"Generated private key: {pvt}")
        base = 13877
        while base in values:
            base = primes[randint(1,len(primes) - 1)]
        values.append(base)
        print(f"Generated base: {base}")
        mod = 14107
        while mod in values:
            mod = primes[randint(1, len(primes) - 1)]

        print(f"Generated mod: {mod}")

        serverKey = base ** pvt % mod
        print(f"Generated key: {serverKey}\n")
        print("Waiting for a connection...")
        while True:
            try:
                c, a = s.accept()
                print(f"Got connection from: {a}\n")

                print("Sending public keys...")
                keys = f"{str(base)} {str(mod)} {str(serverKey)}"
                c.send(bytes(str(keys).encode()))

                print("Getting clientKey...")
                clientKey = int(c.recv(128).decode())
                print(f"Got clientKey: {clientKey}")

                key = clientKey**pvt % mod
                print(f"Generated symmetric key {key}\n")

                print("Ciphering message with Caesar cipher...")  # easiest cipher
                ciphered = caeser(message, key%25 + 1)
                print(f"Generated cipher text = {ciphered}")
                print("Sending cipher...")
                c.send(ciphered.encode())

            except timeout:
                pass

            except Exception as e:
                print(e)

    except KeyboardInterrupt:
        print("Exiting")
        exit()

    except Exception as e:
        print(e)
