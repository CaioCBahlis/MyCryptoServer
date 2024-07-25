import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random


class Server:
    _IsSingleInstance = None
   
    def __init__(self) -> None:
        host = "127.0.0.1"
        port = 65502
        self.sv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sv.bind((host,port))
        self.sv.listen()
        print("Server is now listening")

        self.clients = []
        self.nicknames = []
        self.Public_Key = self.__Generate__RSA__()
        self.__Generate_AES__()

        
    
        self.Receive()

        
    def Receive(self):
        while True:
            client,address = self.sv.accept()
            print(f"connected from {address}")
            Client_Public_Key = self.__SetUp_Encryption__(client)
            
            Message = self.__EncryptMe__("Nick".encode("utf-8"))
            client.send(Message)
            nickname = self.__DecryptMe__(client.recv(1024))


            self.nicknames.append(nickname)
            self.clients.append(client)


            print(f"nickname of the client is: {nickname}")

            Welcome_Message = self.__EncryptMe__(f"{nickname} has joined the chat!".encode("utf-8"))
            self.Broadcast(Welcome_Message, False)

            Byte_Message = "You're connected to the server".encode("utf-8")
            Message = self.__EncryptMe__(Byte_Message)

            client.send(Message)
            thread = threading.Thread(target=self.Handle, args=(client,))
            thread.start()



    def Handle(self, client):
        while True:
            try:
                message = client.recv(1024)
                self.Broadcast(message, False)
            except:
                index = self.clients.index(client)
                self.clients.remove(client)
                client.close()
                self.Broadcast((f" {self.nicknames[index]} has left the chat"), True)
                self.nicknames.remove(self.nicknames[index])
                break
    

    def Broadcast(self, message, Admin):

        for client in self.clients:
            if not Admin:
                client.send(message)
            else:
                client.send(message)


    

    def __SetUp_Encryption__(self, client):
        with open("SV_AES_key", "rb") as f:
            AESKey = f.read()
            f.close()
        

        SvPublicKey = self.Public_Key.export_key()
        client.send(SvPublicKey)
        ClientPublicKeySerialized = client.recv(2048)
        print(f"client public key: {ClientPublicKeySerialized}")

        print("Sending AES_Key", AESKey)
        cipher = PKCS1_OAEP.new(RSA.import_key(ClientPublicKeySerialized))
        message = cipher.encrypt(AESKey)

        client.send(message)


        return ClientPublicKeySerialized

    def __EncryptMe__(self, message):
        with open("SV_AES_key", "rb") as f:
            Aes_Key = f.read()
            f.close()
       
        cipher = AES.new(Aes_Key, AES.MODE_EAX)
        message, tag = cipher.encrypt_and_digest(message)
        nonce = cipher.nonce
        #print(f'{type(cipher), type(message), type(nonce)}')
        AESPAYLOAD = tag+nonce+bytes(message)
        return AESPAYLOAD
    
    def __DecryptMe__(self, ciphertext):
          tag = ciphertext[:16]
          nonce = ciphertext[16:32]
          message = ciphertext[32:]

          with open("SV_AES_key", "rb") as f:
              f.flush()
              Aes_Key = f.read()
              f.close()
            
          countercipher = AES.new(Aes_Key, AES.MODE_EAX, nonce)
          message = countercipher.decrypt_and_verify(message, tag)
          return message.decode("ascii")

    def __Generate__RSA__(self):
        MyRSAKeys = RSA.generate(2048)
        MyPublicKey = MyRSAKeys.public_key()
        MyPrivateKey = MyRSAKeys.export_key()

        with open("SV_Private_Key", "wb") as f:
            f.flush()
            f.write(MyPrivateKey)
            f.close()
        
        return MyPublicKey
    
    
    def __Generate_AES__(self):
        with open("SV_AES_key", "wb") as f:
            f.flush()
            f.write(Random.get_random_bytes(16))
            f.close()

    def write(self):
        while True:
            msg = str(input()).encode("ascii")
            self.Broadcast(msg, False)

def Generate_Server():
    if Server._IsSingleInstance == None:
        MyServer = Server()
        Server.IsSingleInstance = MyServer
        return  MyServer
    else:
        print("An Instance of the Server already exists!")
        return Server._IsSingleInstance

  
MyServer = Generate_Server()
print(MyServer)


        
        
 
        
    