#!/bin/python3

import threading
import time
import queue
import configparser
import sys
import os
import socket
import subprocess



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
