import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

class Client:

    def __init__(self) -> None:

        self.Nickname = str(input("Enter Nickname: "))
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(("127.0.0.1", 65502))
        self.Aes_Key = self.__RSASetup__()

        Wthread = threading.Thread(target=self.write)
        Rthread = threading.Thread(target=self.receive)
        Wthread.start()
        Rthread.start()

    def write(self):
        while True:
            message = f"{self.Nickname}: {input()}"
            Encmessage = self.__EncryptME__(message.encode("utf-8"))
            self.client.send(Encmessage)


    def receive(self):
        while True:
            try:
                message = self.__DecryptMe__(self.client.recv(1024))
                
                
                if message == "Nick":
                    Message = self.__EncryptME__(self.Nickname.encode("utf-8"))
                    self.client.send(Message)
                else:
                    print(message)
            except:
                print("An Error Ocurred")
                self.client.close()
                break



   
    
    def __RSASetup__(self):
        Serialized_Sv_PublicKey = self.client.recv(4096)
        SV_Public_Key = RSA.import_key(Serialized_Sv_PublicKey)
        print(f"Server Serialized PKey: {Serialized_Sv_PublicKey} and not Serialized {SV_Public_Key}  ")
        key = RSA.generate(2048)
        Mypublic_key = key.publickey().export_key()
        Myprivkeythatalsoshouldbeinafile = key.export_key()
        try:
            self.client.send(Mypublic_key)
            print("Public Key Encryption Has Been Established")
        except:
            print("Encryption has failed")
            print("Trying Again...")
            self.client.close()
            self.__RSASetup__()

        
        AES_KEY = self.__AESSetup__(key)

        return AES_KEY
    
    def __AESSetup__(self, key):
        AESKey = self.client.recv(2048)
        

        countercipher = PKCS1_OAEP.new(key)
        AESKey = countercipher.decrypt(AESKey)
        return AESKey

    
    def __DecryptMe__(self, ciphertext):
            tag = ciphertext[:16]
            nonce = ciphertext[16:32]
            message = ciphertext[32:]
                
            countercipher = AES.new(self.Aes_Key, AES.MODE_EAX, nonce)
            message = countercipher.decrypt_and_verify(message, tag)
            return message.decode("ascii")

            
    
    def __EncryptME__(self, message):
        cipher = AES.new(self.Aes_Key, AES.MODE_EAX)
        message, tag = cipher.encrypt_and_digest(message)
        nonce = cipher.nonce
        #print(f'{type(cipher), type(message), type(nonce)}')
        AESPAYLOAD = tag+nonce+bytes(message)
        return AESPAYLOAD
    

MyClient = Client()