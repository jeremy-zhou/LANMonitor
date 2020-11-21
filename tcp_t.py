#!/usr/bin/python

import socket
import sys
import datetime
import struct

tcp_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_s.connect(('192.168.2.241', 2335))
len = 11
itype = 5
len_4bytes = struct.pack('>i', len)
tcp_s.send(len_4bytes)
tcp_s.close()
sys.exit(0)
itype_4bytes = struct.pack('>i', itype)
tcp_s.send(len_4bytes)
tcp_s.send(itype_4bytes)
tcp_s.send(bytes('hello,world'.encode('utf-8')))
rmsg = tcp_s.recv(128)
print(rmsg.decode('utf-8'))

tcp_s.close()
