from Crypto.Cipher import AES
import random

client = 'client1'
riv = bytes(random.randint(0X41, 0X5A) for i in range(16))
physical_key = bytes(random.randint(0X41, 0X5A) for i in range(16))
print(physical_key)
print(riv)
aes = AES.new(b'1234567812345678', AES.MODE_CBC, riv)
# aes = AES.new(b'1234567812345678', AES.MODE_EAX)
ciphered = aes.encrypt(physical_key)
ciphered1 = aes.encrypt(physical_key)
print(ciphered)
print(len(ciphered))
print(ciphered1)
print(len(ciphered1))

aes1 = AES.new(b'1234567812345678', AES.MODE_CBC, riv)
print(aes1.decrypt(ciphered))
# print(bytes(ciphered1[1]))
print(aes1.decrypt(ciphered1))

print(bytearray(b'Z')[0])
print(bytearray(b'<')[0])
# f = open('server_keys/server_key_' + client, 'wb')
# f.write(riv)
# f.write(ciphered)
# f.close()
#
# f = open('key_' + client, 'wb')
# f.write(riv)
# f.write(ciphered)
# f.close()
