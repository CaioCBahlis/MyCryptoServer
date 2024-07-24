import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes



host = "127.0.0.1"
port = 65511


sv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sv.bind((host,port))
sv.listen()

clients = []
nicknames = []

MyKeysthatreallyshouldbeinafile = RSA.generate(2048)
MyPublicKey = MyKeysthatreallyshouldbeinafile.public_key()
SvPrivKeythatmostdefinitelyshouldbeinafile = MyKeysthatreallyshouldbeinafile.export_key()

AESKey = get_random_bytes(16)

def SetUp_Encryption(AESKEY, client):
    SvPublicKey = MyPublicKey.export_key()
    client.send(SvPublicKey)
    ClientPublicKeySerialized = client.recv(2048)
    print(f"client public key: {ClientPublicKeySerialized}")

    cipher = PKCS1_OAEP.new(RSA.import_key(ClientPublicKeySerialized))
    message = cipher.encrypt(AESKEY)

    client.send(message)


    return ClientPublicKeySerialized

def DecryptMe(ciphertext):

    tag = ciphertext[:16]
    nonce = ciphertext[16:32]
    message = ciphertext[32:]
    countercipher = AES.new(AESKey, AES.MODE_EAX, nonce)
    message = countercipher.decrypt_and_verify(message, tag)
    print(message)
    return message

def Broadcast(message, Admin):

    for client in clients:
        if Admin:
            client.send(message.encode("ascii"))
        else:
            client.send(DecryptMe(message))


def handle(client):
    while True:
        try:
            message = client.recv(1024)

            Broadcast(message, False)
        except:
            index = clients.index(client)
            client.remove(client)
            client.close()
            Broadcast((f" {nicknames[index]} has left the chat"), True)
            nicknames.remove(nicknames[index])
            break

def receive():
    while True:
        client,address = sv.accept()
        print(f"connected from {address}")
        SetUp_Encryption(AESKey, client)

        client.send("NICK: ".encode("ascii"))
        nickname = DecryptMe(client.recv(1024))
        nicknames.append(nickname)
        clients.append(client)
        print(f"nickname of the client is {nickname}")
        Broadcast(f"{nickname} has joined the chat!", True)
        client.send(f"You're connected to the server".encode("ascii"))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

def write():
    while True:
        msg = str(input()).encode("ascii")
        Broadcast(msg, False)

writeThread = threading.Thread(target=write)
writeThread.start()

print("Server is Listening")
receive()