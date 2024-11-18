from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def custom_aes_decrypt(key, ciphertext, iv):
    # Ensure the key is either 16, 24, or 32 bytes long
    if len(key) not in [16, 24, 32]:
        raise ValueError("Invalid key length. Key must be 16, 24, or 32 bytes.")
    
    # Create the AES cipher with the same mode and IV as used in encryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=10)
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


with open("sbiedll.dat", "rb") as f:
    data = f.read()

key = bytes.fromhex("489b0bf53b49a8635dde3fdf6d68b487")
iv = bytes.fromhex("9aaacddcf7c1448129081b406238304e")

dec_data = custom_aes_decrypt(key, data, iv)
with open("moonwalk.dll", "wb") as f:
    f.write(dec_data)
