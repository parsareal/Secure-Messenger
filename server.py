import socket
import select
import sys
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
import random
# from thread import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

IP_address = ''
Port = 4096

server.bind((IP_address, Port))

server.listen(100)

list_of_clients = []

MODE = 'RSA'


def get_keys():
	random_generator = Random.new().read
	key = RSA.generate(1024, random_generator)
	private, public = key, key.publickey()
	return private, public


PRIVATE_KEY = ''
PUBLIC_KEY = ''
CLIENTS_PUB_KEYS = None
CHUNK_SIZE = 16

if MODE == 'RSA':
	PRIVATE_KEY, PUBLIC_KEY = get_keys()
	CLIENTS_PUB_KEYS = dict()


def client_thread(conn, addr):

	conn.send(b'Welcome_dear!!!!')
	file_rec_mode = False

	while True:
			try:
				if not file_rec_mode:
					conn.send(b'send_the_command')
				command_type = conn.recv(4).decode()
				destination = conn.recv(7).decode()

				# print(command)
				if command_type and destination:

					# destination = command.split()[1]
					# command_type = command.split()[0]

					# print(command)
					if not check_validity(destination):
						conn.send(b'invalid client!!')
						continue

					if command_type == 'file':
						# size = conn.recv(2)
						riv = conn.recv(16)
						hashed = conn.recv(CHUNK_SIZE)
						ciphered = conn.recv(60000)
						print('iv: ' + str(riv))
						print('encrypted data: ' + str(ciphered))
						send_file(ciphered, destination, riv, addr.encode(), None, hashed, b'new_out_file!!!!', end_file=False)
						file_rec_mode = True

					if command_type == 'endf':
						send_file(None, destination, None, addr.encode(), None, None,  b'end_file!!!!!!!!', end_file=True)
						file_rec_mode = False

					if command_type == 'mesg':
						size = conn.recv(2)
						riv = conn.recv(16)
						hashed = conn.recv(CHUNK_SIZE)
						ciphered = conn.recv(60000)
						print('iv: ' + str(riv))
						print('encrypted data: ' + str(ciphered))
						print('hashed data: ' + str(hashed))
						send_message(ciphered, destination, riv, addr.encode(), size, hashed,  b'new_out_message!')

					if command_type == 'sess':
						conn.send(b'create_session!!')
						if MODE == 'RSA':
							ciphered_session = conn.recv(128)
							cipher = PKCS1_OAEP.new(PRIVATE_KEY)
							session = cipher.decrypt(ciphered_session)
							send_session_key(addr.encode(), destination, session, None)

						else:
							riv = conn.recv(16)
							ciphered_session = conn.recv(16)
							print('iv: ' + str(riv))
							print('ciphered_session: ' + str(ciphered_session))
							send_session_key(addr.encode(), destination, ciphered_session, riv)

					if command_type == 'endd':
						if MODE == 'RSA':
							send_end_session(addr.encode(), destination, None)
						if MODE != 'RSA':
							riv = conn.recv(16)
							print('iv: ' + str(riv))
							send_end_session(addr.encode(), destination, riv)
				else:
					remove(conn)

			except:
				continue


def send_session_key(source, destination, session_key, ivector):
	for clients in list_of_clients:
		if clients[1] == destination:
			try:
				if MODE == 'RSA':
					clients[0].send(b'new_session_key!')
					clients[0].send(source)
					cipher = PKCS1_OAEP.new(CLIENTS_PUB_KEYS[destination])
					ciphered = cipher.encrypt(session_key)
					clients[0].send(ciphered)
				else:
					clients[0].send(b'new_session_key!')
					clients[0].send(ivector)

					clients[0].send(source)
					clients[0].send(session_key)

			except:
				clients[0].close()
				remove(clients)


def send_end_session(source, destination, riv):
	for clients in list_of_clients:
		if clients[1] == destination:
			try:
				clients[0].send(b'end_session_key!')
				clients[0].send(source)
				if MODE != 'RSA':
					clients[0].send(riv)
			except:
				clients[0].close()
				remove(clients)


def check_validity(arg_des):
	tmp = False
	# print(list_of_clients)
	for clients in list_of_clients:
		if clients[1] == arg_des:
			tmp = True
			break
	return tmp


def send_file(message, destination, ivector, source, message_size, hashed, command, end_file):
	for clients in list_of_clients:
		if clients[1] == destination:
			try:
				clients[0].send(command)
				clients[0].send(source)

				if not end_file:
					clients[0].send(ivector)

					# clients[0].send(len(source).to_bytes(length=2, byteorder='big'))

					# clients[0].send(message_size)
					clients[0].send(hashed)
					clients[0].send(message)

			except:
				clients[0].close()
				remove(clients)


def send_message(message, destination, ivector, source, message_size, hashed, command):
	for clients in list_of_clients:
		if clients[1] == destination:
			try:
				clients[0].send(command)
				clients[0].send(source)
				clients[0].send(ivector)
				clients[0].send(message_size)
				clients[0].send(hashed)
				clients[0].send(message)

			except:
				clients[0].close()
				remove(clients)


def remove(connection):
	if connection in list_of_clients:
		list_of_clients.remove(connection)


GLOBAL_CLIENTS_NUM = 0
SESSION_KEYS = dict()
while True:
	conn, addr = server.accept()
	# client_nickname = "client" + str(GLOBAL_CLIENTS_NUM)
	client_nickname = conn.recv(7).decode()
	list_of_clients.append((conn, client_nickname))

	print(addr[0] + "," + client_nickname + " connected")

	if MODE == 'RSA':
		client_public_key = RSA.importKey(conn.recv(1024), passphrase=None)
		print('pub_key: ' + str(client_public_key))
		CLIENTS_PUB_KEYS[client_nickname] = client_public_key
		conn.send(PUBLIC_KEY.exportKey(format='PEM', passphrase=None, pkcs=1))

	threading.Thread(target=client_thread, args=(conn, client_nickname)).start()
	GLOBAL_CLIENTS_NUM += 1

conn.close()
server.close()
