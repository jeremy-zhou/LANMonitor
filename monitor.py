#!/bin/python3

import threading
import time
import queue
import configparser
import datetime
import sys
import os
import socket
import subprocess
import hashlib
import json
import bz2
import base64

EXIT_FLAG = 0

def time_now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_local(s):
    with open('/tmp/monitor.log', 'a+', encoding='utf8') as log:
        log.write('%s ' % time_now_str())
        log.write('%s\n' % s)


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
    log_local(json_str)
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
        log_local(self.name)
        log_local(self.ip_list)
        for ip in self.ip_list:
            self.ip_state[ip] = 0
        self.ping_c = ping_c
        self.ping_o = ping_o
        self.pulse = pulse

    def run(self):
        index = 0;
        exit = 0;
        while exit == 0:
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
                    log_local('%s is down' % ip_crash)
                    self.lock.release()
            index = (index + 1) % len(self.ip_list)
            time.sleep(2)

            self.lock.acquire()
            exit = EXIT_FLAG
            self.lock.release()
        log_local('%s exits' % self.name)

class msgSender (threading.Thread):

    def __init__(self, name, lock, queue, conf, packet_type):
        threading.Thread.__init__(self)
        self.name = name
        self.lock = lock
        self.queue = queue
        self.packet_type = packet_type
        self.conf = conf

    def run(self):
        ip_crash = None

        exit = 0;

        while exit == 0:

            self.lock.acquire()
            if self.queue.qsize():
                ip_crash = self.queue.get()
            self.lock.release()
            
            if ip_crash:
                tcp_sock = None
		while 1:
			try:
                		tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                		tcp_sock.connect((self.conf['host'], self.conf['port']))
			except socket.timeout as e:
				log_local('failed to connect to log server, reason: {0}'.format(e))
				tcp_sock.close()
				tcp_sock = None
			except socket.error as e:
				log_local('failed to connect to log server, reason: {0}'.format(e))
				tcp_sock.close()
				tcp_sock = None
			else:
				log_local('success to connect to log server')
				break
			time.sleep(2)
			ef = 0
			self.lock.acquire()
            		ef = EXIT_FLAG
            		self.lock.release()
			if ef == 1:
				log_local('{0} exits'.format(self.name))
				return
			continue

                check_sign(form_sign(self.conf), self.packet_type, tcp_sock)

                report = {}
                report['cmd'] = self.conf['log_cmd']
                crash_data = {}
                crash_data['$timestamp'] = int(time.time())
                crash_data['$log_type'] = self.conf['$log_type']
                crash_data['area'] = self.conf['area']
                crash_data['machine_name'] = ip_crash
                encoding(report, crash_data, self.packet_type, tcp_sock)

                tcp_sock.close()

                ip_crash = None

            time.sleep(0.5)

            self.lock.acquire()
            exit = EXIT_FLAG
            self.lock.release()

        log_local('%s exits' % self.name)

conf = read_conf("/etc/crash_monitor/monitor.conf")
ip_all = read_ip_list("/etc/crash_monitor/monitor.ip_list")

packet_type = 1

lock = threading.Lock()
Q = queue.Queue(0)
#Q.put('192.168.2.90')
#Q.put('192.168.2.91')
conn_t = msgSender("conn-thread", lock, Q, conf, packet_type)
conn_t.start()

task_list = [ip_all[i:i+conf['ip_cnt_per_thread']] for i in range(0, len(ip_all), conf['ip_cnt_per_thread'])]
t_list = []
for i in range(len(task_list)):
    t_tmp = Monitor('thread-%s' % i, lock, Q, task_list[i], conf['ping_count'], conf['ping_timeout'], conf['pulse_thresh'])
    t_list.append(t_tmp)
    t_tmp.start()

try:
    conn_t.join()
except KeyboardInterrupt:
    lock.acquire()
    EXIT_FLAG = 1
    lock.release()

conn_t.join()
for t in t_list:
    t.join()

log_local('all cleaned')
sys.exit(0)

