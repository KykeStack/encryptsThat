from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from Cryptographys import crypting 
from Crypto.PublicKey import RSA
import json

json_path = "C:\\Users\\Elep13\\Desktop\\sco\\API\\DataBase.json" 
private_key = "C:\\Users\\Elep13\\Desktop\\sco\\API\\keys\\private.pem" 
public_key = "C:\\Users\\Elep13\\Desktop\\sco\\API\\keys\\public.pem"

dyctio = {
    "numbers": {1: "One", 2: "Two", 3: "Three"},
    "capital_city" : {"Nepal": "Kathmandu", "England": "London"},
    "student_id" : {111: "Eric", 112: "Kyle", 113: "Butters"}
}

data = json.dumps(dyctio).encode('utf-8')
content = crypting.encrypt(data, publicKeyFile=public_key)

print(content)          















# Assuming your private key is stored in a file called "private_key.pem"
# with open("private_key.pem", "rb") as key_file:
#     private_key = load_pem_private_key(
#         key_file.read(),
#         password=None  # If your private key is password-protected, specify the password here
#     )


# Assuming your private key is loaded in `private_key` variable
# and the data to be decrypted is loaded in `encrypted_data` variable
# decrypted_data = private_key.decrypt(
#     content,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )

# with open(private_key, 'rb') as f:
#     privateKey = f.read()
#     # create private key object
#     key = RSA.import_key(privateKey)
                        
# encryptedSessionKey, nonce, tag, ciphertext = [x for x in (key.size_in_bytes(), 16, 16, -1) ]

# print(encryptedSessionKey, nonce, tag, ciphertext )
# decode = crypting.decrypt(private_key, dataFile=json_path)
# print(decode)



    
        