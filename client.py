# Python program to implement client side of chat room. 
import socket 
import select 
import sys 
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
from tkinter.filedialog import askopenfilename
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import threading
import hashlib

from tkinter import Tk

SESSION_KEYS = dict()
MODE = 'RSA'
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(len(sys.argv))
if len(sys.argv) != 2:
    print("Enter the client id")
    exit()
IP_address = ''
client_id = str(sys.argv[1])
Port = 4096
server.connect((IP_address, Port))

server.send(client_id.encode())


def get_keys():
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    private, public = key, key.publickey()
    return private, public


PRIVATE_KEY = ''
PUBLIC_KEY = ''
PHYSICAL_KEYS = ''
SERVER_PUBLIC_KEY = ''
ENDED_SESSIONS = dict()
CHUNK_SIZE = 16

if MODE == 'RSA':
    print('salam')
    PRIVATE_KEY, PUBLIC_KEY = get_keys()
    print(PUBLIC_KEY)
    server.send(PUBLIC_KEY.exportKey(format='PEM', passphrase=None, pkcs=1))
    SERVER_PUBLIC_KEY = RSA.importKey(server.recv(1024), passphrase=None)

else:
    # f = open('physical_key', 'rb')
    # iv = f.read(16)
    # ciphered = f.read(16)
    # f.close()
    # aes = AES.new(b'1234567812345678', AES.MODE_CBC, iv)
    # PHYSICAL_KEY = aes.decrypt(ciphered)
    # print('physical key: ' + str(PHYSICAL_KEY))
    PHYSICAL_KEYS = dict()


def generate_new_sessionkey(destination_address, client_key, command):
    if not ENDED_SESSIONS[destination_address]:
        # server.send(command.encode())
        server.send('sess'.encode())
        server.send(destination_address.encode())
        ack = server.recv(16)

        if ack == b'create_session!!':
            SESSION_KEY = bytes(random.randint(0, 0XFF) for i in range(16))
            print('new session key for {}'.format(destination_address))

            if MODE == 'RSA':
                cipher = PKCS1_OAEP.new(client_key)
                ciphered = cipher.encrypt(SESSION_KEY)
                print(len(ciphered))
                server.send(ciphered)
            # print('ciphered: ' + str(ciphered))

            else:
                # server.send(len(destination_address.encode()).to_bytes(length=2, byteorder='big'))
                # server.send(destination_address.encode())

                ivector = bytes(random.randint(0, 0XFF) for i in range(16))
                aes = AES.new(client_key, AES.MODE_CBC, ivector)
                server.send(ivector)
                ciphered_session = aes.encrypt(SESSION_KEY)
                server.send(ciphered_session)
                print('iv: ' + str(ivector))
                print('ciphered_session: ' + str(ciphered_session))

            SESSION_KEYS[destination_address] = SESSION_KEY
            print('session key: ' + str(SESSION_KEYS[destination_address]))
            threading.Timer(20, generate_new_sessionkey, args=(destination_address, client_key, command)).start()


def read_physical_key(source):
    f = open(client_id + '/' + source, 'rb')
    iv = f.read(16)
    ciphered = f.read(16)
    f.close()
    aes = AES.new(b'1234567812345678', AES.MODE_CBC, iv)
    PHYSICAL_KEYS[source] = aes.decrypt(ciphered)
    print('physical key: ' + str(PHYSICAL_KEYS[source]) + 'for: ' + source)


def read_in_chunks(file_object, chunk_size):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


request = None
# SESSION_KEY = None
FILE_BUFFER = list()
VALID_FILE = True

while True:
    sockets_list = [sys.stdin, server]

    read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])
    for socks in read_sockets:
        if socks == server:
            message = socks.recv(16)
            print()
            print(message)

            if message == b'invalid client!!':
                pass

            if message == b'new_session_key!':
                if MODE == 'RSA':
                    source_name = server.recv(7)
                    key = server.recv(128)

                    cipher = PKCS1_OAEP.new(PRIVATE_KEY)
                    SESSION_KEY = cipher.decrypt(key)
                else:
                    riv = server.recv(16)

                    source_name = server.recv(7)
                    read_physical_key(source_name.decode())
                    key = server.recv(16)

                    print('iv: ' + str(riv))
                    print('ciphered_session: ' + str(key))

                    aes = AES.new(PHYSICAL_KEYS[source_name.decode()], AES.MODE_CBC, riv)
                    SESSION_KEY = aes.decrypt(key)

                SESSION_KEYS[source_name.decode()] = SESSION_KEY
                ENDED_SESSIONS[source_name.decode()] = False
                print('session key: ' + str(SESSION_KEY) + ' for: ' + source_name.decode())

            if message == b'end_session_key!':
                source_name = server.recv(7)
                print(source_name.decode())
                try:
                    if MODE != 'RSA':
                        riv = server.recv(16)
                        aes = AES.new(b'1234567812345678', AES.MODE_CBC, riv)
                        ciphered = aes.encrypt(SESSION_KEYS[source_name.decode()])
                        print('iv: ' + str(riv))
                        print('ciphered_physical: ' + str(ciphered))
                        f = open(client_id + '/' + source_name.decode(), 'wb')
                        f.write(riv)
                        f.write(ciphered)
                        f.close()
                    SESSION_KEYS[source_name.decode()] = None
                    ENDED_SESSIONS[source_name.decode()] = True
                except:
                    print('invalid session_end request')

            if message == b'new_out_message!':
                source_name = server.recv(7)
                ENDED_SESSIONS[source_name.decode()] = True

                riv = server.recv(16)

                print('message from: ' + source_name.decode())

                size = server.recv(2)
                hashed = server.recv(16)
                content = server.recv(60000)
                print('size: ' + str(size))
                print('riv: ' + str(riv))
                print('ciphered: ' + str(content))
                print('hashed: ' + str(hashed))

                aes = AES.new(SESSION_KEYS[source_name.decode()], AES.MODE_CBC, riv)
                data = aes.decrypt(content)
                msg = data[:int.from_bytes(size, 'big')]
                new_hashed = hashlib.md5(msg).digest()

                if new_hashed == hashed:
                    print(source_name.decode() + '-> ' + msg.decode())
                else:
                    print('Message has been manipulated')
                ENDED_SESSIONS[source_name.decode()] = False

            if message == b'new_out_file!!!!':
                source_name = server.recv(7)
                ENDED_SESSIONS[source_name.decode()] = True

                riv = server.recv(16)
                # size = server.recv(2)
                hashed = server.recv(CHUNK_SIZE)
                content = server.recv(CHUNK_SIZE)
                # print('size: ' + str(size))
                print('riv: ' + str(riv))
                print('ciphered: ' + str(content))

                aes = AES.new(SESSION_KEYS[source_name.decode()], AES.MODE_CBC, riv)
                data = aes.decrypt(content)
                print('hashed: ' + str(hashed))
                data = data.rstrip(b'\x08')
                data = data.rstrip(b'\t')
                print(data)

                if hashed == hashlib.md5(data).digest():
                    print('successful')
                    FILE_BUFFER.append(data)
                else:
                    print('File has been manipulated')
                    VALID_FILE = False

                # t = time.localtime()
                # savef = open(source_name.decode() + '_to_' + client_id + '_' + str(t.tm_year) + '-' + str(t.tm_yday) + '-' + str(t.tm_hour) + '-' + str(
                #     t.tm_min), 'wb')
                # savef.write(data[:int.from_bytes(size, 'big')])
                # savef.close()

            if message == b'end_file!!!!!!!!':
                source_name = server.recv(7)
                if VALID_FILE:
                    t = time.localtime()
                    savef = open(
                        source_name.decode() + '_to_' + client_id + '_' + str(t.tm_year) + '-' + str(t.tm_yday) + '-' + str(
                            t.tm_hour) + '-' + str(
                            t.tm_min), 'wb')
                    print(len(FILE_BUFFER))
                    for l in FILE_BUFFER:
                        savef.write(l)
                    savef.close()
                    FILE_BUFFER = list()
                VALID_FILE = True

        else:
            phrase = sys.stdin.readline()
            command_type = phrase.split()[0]
            destination = phrase.split()[1]
            command = command_type + " " + destination
            try:
                if command_type == 'file':
                    if destination not in SESSION_KEYS.keys():
                        print('please make a session key')
                        continue
                    ENDED_SESSIONS[destination] = True

                    fpath = askopenfilename(title='choose the file you want to send')
                    f = open(fpath, 'rb')
                    data = read_in_chunks(f, CHUNK_SIZE)
                    counter = 0
                    for d in data:
                        iv = bytes(random.randint(0, 0xff) for i in range(16))
                        aes = AES.new(SESSION_KEYS[destination], AES.MODE_CBC, iv)
                        ciphered = aes.encrypt(pad(data_to_pad=d, block_size=AES.block_size))
                        print('riv: ' + str(iv))
                        # if len(d) < CHUNK_SIZE:
                        #     tmp = d.decode()
                        #     while len(tmp) != 16:
                        #         tmp = tmp + " "
                        #     d = tmp.encode()
                        print('ciphered: ' + str(ciphered))
                        hashed_data = hashlib.md5(d).digest()
                        print('hashed: ' + str(hashed_data))
                        print(d)
                        server.send(command_type.encode())
                        server.send(destination.encode())
                        server.send(iv)
                        server.send(hashed_data)
                        server.send(ciphered[:16])
                        time.sleep(0.3)
                        counter += 1
                        print()
                    print(counter)
                    server.send('endf'.encode())
                    server.send(destination.encode())
                    ENDED_SESSIONS[destination] = False

                elif phrase.split()[0] == 'message':
                    if destination not in SESSION_KEYS.keys():
                        print('please make a session key')
                        continue
                    ENDED_SESSIONS[destination] = True
                    iv = bytes(random.randint(0, 0xff) for i in range(16))
                    aes = AES.new(SESSION_KEYS[destination], AES.MODE_CBC, iv)
                    raw_data = phrase.split(" ", 2)[2].encode()
                    data = aes.encrypt(pad(data_to_pad=raw_data, block_size=AES.block_size))
                    hashed_data = hashlib.md5(raw_data).digest()
                    print('hashed: ' + str(hashed_data))
                    print(len(hashed_data))
                    print('iv: ' + str(iv))
                    print('encrypted data: ' + str(data))
                    server.send('mesg'.encode())
                    server.send(destination.encode())
                    server.send(len(raw_data).to_bytes(length=2, byteorder='big'))
                    server.send(iv)
                    server.send(hashed_data)
                    server.send(data)
                    ENDED_SESSIONS[destination] = False

                elif phrase.split()[0] == 'session':
                    ENDED_SESSIONS[destination] = False
                    if MODE == 'RSA':
                        generate_new_sessionkey(destination, SERVER_PUBLIC_KEY, command)
                    else:
                        print('generate new session key')
                        read_physical_key(destination)
                        generate_new_sessionkey(destination, PHYSICAL_KEYS[destination], command)

                elif phrase.split()[0] == 'end':
                    server.send('endd'.encode())
                    server.send(destination.encode())
                    if MODE != 'RSA':
                        iv = bytes(random.randint(0X00, 0XFF) for i in range(16))
                        aes = AES.new(b'1234567812345678', AES.MODE_CBC, iv)
                        ciphered = aes.encrypt(SESSION_KEYS[destination])
                        print('iv: ' + str(iv))
                        print('ciphered_physical: ' + str(ciphered))
                        server.send(iv)
                        f = open(client_id + '/' + destination, 'wb')
                        f.write(iv)
                        f.write(ciphered)
                        f.close()
                    SESSION_KEYS[destination] = None
                    ENDED_SESSIONS[destination] = True
                else:
                    print('Invalid command!')
            except Exception as e:
                print(e)

            sys.stdout.flush()
server.close()
