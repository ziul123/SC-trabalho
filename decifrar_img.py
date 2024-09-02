from ctr import aes_ctr_decrypt

if __name__ == "__main__":
    key = bytes.fromhex('30313233343536373839616263646566')  #('0123456789abcdef' em hexadecimal) 
    nonce = bytes.fromhex('66656463626139383736353433323130')  #('fedcba9876543210' em hexadecimal)
    filename = input("Qual arquivo decifrar? ")
    num_rounds = int(input("Quantas rodadas? "))
    print(f"Decifrando arquivo {filename}...")
    with open(filename, "rb") as f:
        ciphertext = f.read()

    plaintext = aes_ctr_decrypt(ciphertext, key, nonce, num_rounds-1)
    with open(filename[:-4] + "_decifrado.jpg", "wb+") as f:
        f.write(plaintext)
    print("Decifração finalizada.")
