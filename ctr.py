from aes import aes_ecb_encrypt, aes_ecb_decrypt

def increment_counter(counter: bytes) -> bytes:
    counter_int = int.from_bytes(counter, byteorder='big') + 1
    return counter_int.to_bytes(len(counter), byteorder='big')

def aes_ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes, num_rounds: int) -> bytes:
    ciphertext = bytearray()
    counter = nonce

    for i in range(0, len(plaintext), 16):
        # Encripta o contador usando AES
        keystream = aes_ecb_encrypt(counter, key, num_rounds)
        block = plaintext[i:i+16]
        
        # Aplica XOR entre o bloco de texto plano e o keystream
        encrypted_block = bytes([b ^ k for b, k in zip(block, keystream)])
        ciphertext.extend(encrypted_block)

        
        counter = increment_counter(counter)

    return bytes(ciphertext)

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, num_rounds: int) -> bytes:
    # Decriptação no modo CTR é igual à encriptação
    return aes_ctr_encrypt(ciphertext, key, nonce, num_rounds)


if __name__ == "__main__":
    key = bytes.fromhex('30313233343536373839616263646566')  #('0123456789abcdef' em hexadecimal) 
    nonce = bytes.fromhex('66656463626139383736353433323130')  #('fedcba9876543210' em hexadecimal)
    plaintext = b'Texto de exemplo para encriptar usando AES CTR'
    num_rounds = 9 #isso faz a 1º rodada + 9 do laço = 10 rodadas que é o padrão do aes 128 bits. Culpa sua Paulo suahsuah

    # Encriptação
    encrypted = aes_ctr_encrypt(plaintext, key, nonce, num_rounds)
    print(f"Encrypted: {encrypted.hex()}")

    # Decriptação
    decrypted = aes_ctr_decrypt(encrypted, key, nonce, num_rounds)
    print(f"Decrypted: {decrypted}")

    # Printar chave e nonce para testes com OpenSSL
    print(f"Key: {key.hex()}")
    print(f"Nonce: {nonce.hex()}")


#################### comandos que usei no openssl para comparar ####################
'''
echo -n "Texto de exemplo para encriptar usando AES CTR" > plaintext.txt

key="30313233343536373839616263646566"  # Hexadecimal para '0123456789abcdef'
nonce="66656463626139383736353433323130"  # Hexadecimal para 'fedcba9876543210'
openssl enc -aes-128-ctr -in plaintext.txt -out encrypted.bin -K $key -iv $nonce

xxd -p encrypted.bin


'''
