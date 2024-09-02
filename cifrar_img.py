from ctr import aes_ctr_encrypt

if __name__ == "__main__":
    key = bytes.fromhex('30313233343536373839616263646566')  #('0123456789abcdef' em hexadecimal) 
    nonce = bytes.fromhex('66656463626139383736353433323130')  #('fedcba9876543210' em hexadecimal)
    filename = input("Qual arquivo cifrar? ")
    print(f"Cifrando arquivo {filename}...")
    with open(filename, "rb") as f:
        plaintext = f.read()
    
    for i in [1, 5, 9, 13]:
        ciphertext = aes_ctr_encrypt(plaintext, key, nonce, i-1)
        with open(filename[:-4] + f"_{i}.jpg", "wb+") as f:
            f.write(ciphertext)
        print(f"Terminada cifração com {i} rodadas")

    print("Cifração finalizada.")
