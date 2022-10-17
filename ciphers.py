# For using custom encryption algorithms

def caeser(message: str, key: int) -> str:
    # Full implementation of this cipher is not required
    ciphered = ''
    for i in message:
        shifted = ord(i) - key
        ciphered += chr(shifted)
    return ciphered

if __name__ == "__main__":
    ciphered = caeser("Hello", 3)
    print(ciphered)
    print(caeser(ciphered, -3))