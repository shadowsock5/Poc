#coding=utf-8
import struct
import binascii
import socket

host = "127.0.0.1" #"192.168.85.1"   # 
port = 1080

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
socket.setdefaulttimeout(5)

s.connect((host,port))

hello = b'\x05\x02\x00\x02'

print(hello)

# 第一次（握手）
s.send(hello)

data1=s.recv(1024)
print(data1)

user = 'cqq'
passwd = 'pass'

#payload = b'\x01\x03\x63\x71\x71\x04\x70\x61\x73\x72'
#payload = b'\x01' + struct.pack('>H', len(user)) + user.encode() + struct.pack('>H', len(passwd)) + passwd.encode()
user_len_b =  struct.pack('b', len(user))    # 使用b的时候，才是一个字节，否则使用>H 为两个字节
user_b =      user.encode()

pass_len_b =  struct.pack('b', len(passwd))
pass_b =      passwd.encode()

payload = b'\x01' + user_len_b +  user_b + pass_len_b + pass_b
print(payload)

# 第二次（认证）

s.send(payload)

data2=s.recv(1024)
print(data2)
print(data2[1])
print(type(data2[1]))

if data2[1] == 0:
	print("success!")


s.close()
