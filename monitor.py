#!/bin/python3

import threading
import time
import queue
import configparser
import sys
import os
import socket
import subprocess
import hashlib
import json
import bz2
import base64

def upload_sign(pub_args, i_type, host, port):

    timestamp = int(time.time())
    pub_args["data"]["$timestamp"] = timestamp
    print(repr(pub_args))
    last_i = timestamp % 10
    i_tmp = int(timestamp / 10)
    i_tmp = int(i_tmp / 10)
    rev_third_i = i_tmp % 10
    print(last_i, rev_third_i)

    data = pub_args["data"]
    s_keys = sorted(data)
    check_str = str(rev_third_i)
    for k in s_keys:
        check_str = check_str + "%s=%s" % (k, data[k])
    check_str = check_str + str(last_i)
    print(check_str)
    data["$sign"] = hashlib.md5(check_str.encode("utf-8")).hexdigest()
    print(repr(pub_args))

    json_str = json.dumps(pub_args)
    json_str_len = len(json_str)
    data_len_4bytes = json_str_len.to_bytes(4, 'big')
    type_4bytes = i_type.to_bytes(4, 'big')
    
    addr = (host, port)
    t_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t_sock.connect(addr)
    t_sock.send(data_len_4bytes)
    t_sock.send(type_4bytes)
    t_sock.send(bytes(json_str.encode('utf-8')))
    msg = t_sock.recv(128)
    print(msg.decode('utf-8'))
    print(len(msg))
    returned_json_str = msg.decode('utf-8')
    ind = returned_json_str.find('{')
    json_str = returned_json_str[ind:]
    print(json_str)
    obj = json.loads(json_str)
    print(obj["msg"])
    encoding(t_sock)

def encoding(arg_sock):
    
    pub = {}
    pub["cmd"] = "/log/report/driver"

    crash_data = {}
    crash_data["$timestamp"] = 1605251401
    crash_data["$log_type"] = "crash"
    crash_data["area"] = "hb4"
    crash_data["machine_name"] = "127.0.0.1"

    json_str = json.dumps(crash_data)
    json_str = json_str.replace(' ','')
    print(json_str)
    json_str = bz2.compress(json_str.encode('utf-8'))
    b64 = base64.b64encode(json_str)
    print(b64.decode('utf-8'))

    log = {}
    log['log'] = b64.decode('utf-8')
    pub['data'] = log

    json_str = json.dumps(pub)
    json_str_len = len(json_str)
    print(json_str_len)
    data_len_4bytes = json_str_len.to_bytes(4, 'big')
    type_4bytes = (1).to_bytes(4, 'big')
    
    arg_sock.send(data_len_4bytes)
    arg_sock.send(type_4bytes)
    arg_sock.send(bytes(json_str.encode('utf-8')))
    msg = arg_sock.recv(128)
    arg_sock.close()
    print(msg.decode('utf-8'))


def upload_crash(area, machine_name, i_type, host, port):

    
    pub = {}
    pub["cmd"] = "log/report/driver"

    crash_data = {}
    crash_data["$timestamp"] = int(time.time())
    crash_data["$log_type"] = "crash"
    crash_data["area"] = "hb4"
    crash_data["machine_name"] = "127.0.0.1"
    print(repr(crash_data))
    raw_json_str = json.dumps(crash_data)
    raw_json_str = raw_json_str.replace(' ', '')
    c = bz2.compress(raw_json_str.encode('utf-8'))
    b64 = base64.b64encode(c)
    compressed = {}
    compressed["log"] = b64.decode('utf-8')
    pub['data'] = compressed
    print(repr(pub)) 
    json_str = json.dumps(pub)
    json_str_len = len(json_str)
    print(json_str_len)
    data_len_4bytes = json_str_len.to_bytes(4, 'big')
    type_4bytes = i_type.to_bytes(4, 'big')
    
    addr = (host, port)
    t_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t_sock.connect(addr)
    t_sock.send(data_len_4bytes)
    t_sock.send(type_4bytes)
    t_sock.send(bytes(json_str.encode('utf-8')))
    #t_sock.shutdown(socket.SHUT_WR)
    msg = t_sock.recv(128)
    t_sock.close()
    print(msg.decode('utf-8'))
    print(len(msg))





def read_conf(conf_file):
    args = {}
    g = configparser.ConfigParser()
    g.read(conf_file)
    args['area'] = g['conf']['area']
    args['ping_count'] = int(g['conf']['ping_c'])
    args['ping_timeo'] = int(g['conf']['ping_o'])
    args['pulse_count'] = int(g['conf']['pulse'])
    args['cnt_per_t'] = int(g['conf']['cnt_per_t'])
    args['host'] = g['remote']['host']
    args['port'] = int(g['remote']['port'])
    return args

def read_pub(pub_file):
    pub = {}
    data = {}
    conf = configparser.ConfigParser()
    conf.read(pub_file)
    pub["cmd"] = conf["pub"]["cmd"]
    data["$who"] = conf["data"]["$who"]
    data["$debug"] = int(conf["data"]["$debug"])
    data["$driver_name"] = conf["data"]["$driver_name"]
    data["$wan_ip"] = conf["data"]["$wan_ip"]
    data["$lan_ip"] = conf["data"]["$lan_ip"]
    pub["data"] = data
    return pub
    

def read_ip_list(ip_list_file):
    
    with open(ip_list_file, 'r') as f:
        ip_all = f.read().splitlines()
        print(ip_all)
        return ip_all

class Monitor (threading.Thread):
    def __init__(self, name, lock, queue, ip_list, ping_c, ping_o, pulse):
        
        threading.Thread.__init__(self)

        self.name = name
        self.lock = lock
        self.queue = queue
        self.ip_list = ip_list
        self.ip_state = {}
        print(self.ip_list)
        for ip in self.ip_list:
            self.ip_state[ip] = 0
        self.ping_c = ping_c
        self.ping_o = ping_o
        self.pulse = pulse

    def run(self):
        index = 0;
        while 1:
            ip_ping = self.ip_list[index]
            process = subprocess.Popen(['ping', ip_ping, '-c', str(self.ping_c), '-W', str(self.ping_o)],
                    stdout = subprocess.PIPE,
                    stderr = subprocess.STDOUT)
            returncode = process.wait()
            if returncode == 0:
                self.ip_state[ip_ping] = returncode
            else:
                self.ip_state[ip_ping] = self.ip_state[ip_ping] + 1
                if self.ip_state[ip_ping] == self.pulse:
                    self.lock.acquire()
                    self.queue.put(ip_ping) 
                    self.lock.release()
            index = (index + 1) % len(self.ip_list)
            time.sleep(0.1)

class msgSender (threading.Thread):

    def __init__(self, name, lock, queue, arg_host, arg_port):
        threading.Thread.__init__(self)
        self.name = name
        self.lock = lock
        self.queue = queue
        self.r_addr = (arg_host,arg_port)
        print(self.r_addr)

    def run(self):
        ip_crash = None
        while 1:

            self.lock.acquire()
            if self.queue.qsize():
                ip_crash = self.queue.get()
            self.lock.release()
            
            if ip_crash:
                tcp_c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_c.connect(self.r_addr)
                tcp_c.send(bytes(ip_crash.encode('utf-8')))
                tcp_c.shutdown(socket.SHUT_WR)
                tcp_c.close()
                ip_crash = None

            time.sleep(0.1)

args = read_conf("./monitor.conf")
ip_all = read_ip_list("./monitor.ip_list")
pub = read_pub("./monitor.pub")
upload_sign(pub, 1, args['host'], args['port'])
#upload_crash('hb4', '192.168.2.241', 2, args['host'], args['port'])
sys.exit(1)

lock = threading.Lock()
Q = queue.Queue(0)
conn_t = msgSender("conn-thread", lock, Q, args['host'], args['port'])
conn_t.start()

task_list = [ip_all[i:i+args['cnt_per_t']] for i in range(0, len(ip_all), args['cnt_per_t'])]
print(task_list)
for task in task_list:
    t_tmp = Monitor("", lock, Q, task, args['ping_count'], args['ping_timeo'], args['pulse_count'])
    t_tmp.start()



conn_t.join()
