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

def log_local(s):
    print(s)


def check_sign(sign_args, i_type, conn):

    timestamp = int(time.time())
    sign_args["data"]["$timestamp"] = timestamp

    last_i = timestamp % 10
    i_tmp = int(timestamp / 10)
    i_tmp = int(i_tmp / 10)
    rev_third_i = i_tmp % 10

    data = sign_args["data"]
    s_keys = sorted(data)
    check_str = str(rev_third_i)
    for k in s_keys:
        check_str = check_str + "%s=%s" % (k, data[k])
    check_str = check_str + str(last_i)
    log_local(check_str)
    data["$sign"] = hashlib.md5(check_str.encode("utf-8")).hexdigest()
    log_local(repr(sign_args))

    json_str = json.dumps(sign_args)
    json_str_len = len(json_str)
    data_len_4bytes = json_str_len.to_bytes(4, 'big')
    type_4bytes = i_type.to_bytes(4, 'big')
    
    conn.send(data_len_4bytes)
    conn.send(type_4bytes)
    conn.send(bytes(json_str.encode('utf-8')))
    returnmsg = conn.recv(128)
    returnmsg = returnmsg.decode('utf-8')
    log_local(returnmsg)


def encoding(report, crash_data, packet_type, conn):
    

    json_str = json.dumps(crash_data)
    json_str = json_str.replace(' ','')
    log_local(json_str)
    json_str = bz2.compress(json_str.encode('utf-8'))
    b64 = base64.b64encode(json_str)
    b64 = b64.decode('utf-8')
    log_local(b64)

    data = { 'log':b64 }
    report['data'] = data

    json_str = json.dumps(report)
    json_str_len = len(json_str)
    log_local(json_str_len)
    data_len_4bytes = json_str_len.to_bytes(4, 'big')
    type_4bytes = packet_type.to_bytes(4, 'big')
    
    conn.send(data_len_4bytes)
    conn.send(type_4bytes)
    conn.send(bytes(json_str.encode('utf-8')))
    returnmsg = conn.recv(128)
    log_local(returnmsg.decode('utf-8'))



def form_sign(conf_dict):

    sign = {}
    data = {}

    data["$who"] = conf_dict["$who"]
    data["$debug"] = conf_dict["$debug"]
    data["$driver_name"] = conf_dict["$driver_name"]
    data["$wan_ip"] = conf_dict["$wan_ip"]
    data["$lan_ip"] = conf_dict["$lan_ip"]

    sign['cmd'] = conf_dict['sign_cmd']
    sign['data']= data

    return sign
    


def read_conf(conf_file):

    conf = {}
    
    p = configparser.ConfigParser()
    p.read(conf_file)

    conf['ping_count']   = int(p['action']['packet_cnt_per_ping'])
    conf['ping_timeout'] = int(p['action']['ping_timeout'])
    conf['pulse_thresh'] = int(p['action']['failed_cnt_thresh'])
    conf['ip_cnt_per_thread'] = int(p['action']['ip_cnt_per_thread'])
    
    conf['host'] = p['log_server']['host']
    conf['port'] = int(p['log_server']['port'])

    conf['area']     = p['report']['area']
    conf['sign_cmd'] = p['report']['sign_cmd']
    conf['log_cmd']  = p['report']['log_cmd']
    conf['$log_type']  = p['report']['$log_type']
    conf['$debug']   = int(p['report']['$debug'])
    conf['$who']     = p['report']['$who']
    conf['$driver_name'] = p['report']['$driver_name']
    conf['$wan_ip'] = p['report']['$wan_ip']
    conf['$lan_ip'] = p['report']['$lan_ip']
    
    log_local(repr(conf))

    return conf
   

def read_ip_list(ip_list_file):
    
    with open(ip_list_file, 'r') as f:
        ip = f.read().splitlines()
        log_local(ip)
        return ip

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

conf = read_conf("./monitor.conf")
ip_all = read_ip_list("./monitor.ip_list")

packet_type = 1

tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.connect((conf['host'], conf['port']))
check_sign(form_sign(conf), packet_type, tcp_sock)
report = {}
report['cmd'] = conf['log_cmd']
crash_data = {}
crash_data['$timestamp'] = int(time.time())
crash_data['$log_type'] = conf['$log_type']
crash_data['area'] = conf['area']
crash_data['machine_name'] = '192.168.2.240'
encoding(report, crash_data, 1, tcp_sock)
tcp_sock.close()
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
