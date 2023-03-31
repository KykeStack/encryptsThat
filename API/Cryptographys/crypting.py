
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import os

def encrypt(content, publicKeyFile, dataFile = None):
    '''
    use EAX mode to allow detection of unauthorized modifications
    '''
        # read public key from file
    with open(publicKeyFile, 'rb') as f:
        publicKey = f.read()

    # create public key object
    key = RSA.import_key(publicKey)
    sessionKey = os.urandom(16)

    # encrypt the session key with the public key
    cipher = PKCS1_OAEP.new(key)
    encryptedSessionKey = cipher.encrypt(sessionKey)

    # read data from file
    if dataFile is not None:
        with open(dataFile, 'rb') as f:
            data = f.read()
            data = bytes(data)
            [ fileName, fileExtension ] = dataFile.split('.')
            encryptedFile = fileName + '_encrypted.' + fileExtension
            cipher = AES.new(sessionKey, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            []

            # save the encrypted data to file
            with open(encryptedFile, 'wb') as f:
                [ f.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext) ]
                print('Encrypted file saved to ' + encryptedFile)
    else:
        data = content

        # encrypt the data with the session key
        cipher = AES.new(sessionKey, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        lista_bytes = []
        for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext):
           lista_bytes.append(x)
        
        # for encypt in (encryptedSessionKey, cipher.nonce, tag, ciphertext):
        #     dict_data["Content"].append[encrypt]
        return lista_bytes
    

def decrypt(privateKeyFile: str,  dataFile: str):
    '''
    use EAX mode to allow detection of unauthorized modifications
    '''
    # read private key from file
    with open(privateKeyFile, 'rb') as f:
        privateKey = f.read()
        # create private key object
        key = RSA.import_key(privateKey)

    # read data from file
    with open(dataFile, 'rb') as f:
        # read the session key
        encryptedSessionKey, nonce, tag, ciphertext = [ f.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]
        print( encryptedSessionKey, nonce, tag, ciphertext)

    # decrypt the session key
    cipher = PKCS1_OAEP.new(key)
    sessionKey = cipher.decrypt(encryptedSessionKey)

    # decrypt the data with the session key
    cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # save the decrypted data to file
    [ fileName, fileExtension ] = dataFile.split('.')
    decryptedFile = fileName + '_decrypted.' + fileExtension
    with open(decryptedFile, 'wb') as f:
        f.write(data)

    print('Decrypted file saved to ' + decryptedFile)

if __name__ == '__main__':
    pass
    # public_key = "C:\\Users\\Elep13\\Desktop\\sco\\encription_2\\public.pem"
    # data_ecrypt = "C:\\Users\\Elep13\\Desktop\\sco\\encription_2\\content.txt"
    # encrypt(data_ecrypt, public_key)

    # private_key = "C:\\Users\\Elep13\\Desktop\\sco\\encription_2\\private.pem"
    # data_decrypt = "C:\\Users\\Elep13\\Desktop\\sco\\encription_2\\content_encrypted.txt"
    # decrypt(data_decrypt, private_key)