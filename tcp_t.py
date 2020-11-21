#!/usr/bin/python3

import socket
import sys
import datetime

print(datetime.datetime.now().strftime("%Y-%m-%d@%H:%M:%S"))
sys.exit(1)
tcp_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_s.connect(('192.168.2.241', 2335))
len = 11
itype = 5
len_4bytes = len.to_bytes(4, 'big')
itype_4bytes = itype.to_bytes(4, 'big')
tcp_s.send(len_4bytes)
tcp_s.send(itype_4bytes)
tcp_s.send(bytes('hello,world'.encode('utf-8')))
rmsg = tcp_s.recv(128)
print(rmsg.decode('utf-8'))

tcp_s.close()
