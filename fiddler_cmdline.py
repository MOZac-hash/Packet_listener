# coding=utf-8
import datetime
import threading
import time

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import *
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

# Threads_Events
stop_sniff_event = threading.Event()
pause_sniff_event = threading.Event()
# ···total_catched
sniff_count = 0
# ···sniff_context
sniff_array = []


# change timestamp to real time
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


# 生产函数
def packet_producer():
    sniff(prn=lambda pkt: packet_consumer(pkt), stop_filter=lambda pkt: stop_sniff_event.is_set(),
          filter='', iface=interface_chosen)


# 消费者
def packet_consumer(pkt):
    global sniff_count
    global sniff_array
    if not pause_sniff_event.is_set():
        sniff_count = sniff_count + 1
        sniff_array.append(pkt)
        global packet_time
        packet_time = timestamp2time(pkt.time)
        # 推导数据包的协议类型
        proto_names = ['TCP', 'UDP', 'ICMP', 'IPv6', 'IP', 'ARP', 'Ether', 'Unknown']
        proto = ''
        for pn in proto_names:
            if pn in pkt:
                proto = pn
                break
        if proto == 'ARP' or proto == 'Ether':
            src = pkt.src
            dst = pkt.dst
        else:
            if 'IPv6' in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
            elif 'IP' in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
        length = len(pkt)
        info = pkt.summary()


# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def start_capture():
    global sniff_count
    global sniff_array
    if stop_sniff_event.is_set():
        sniff_count = 0
        sniff_array.clear()
        stop_sniff_event.clear()
        pause_sniff_event.clear()
    else:
        sniff_count = 0
        sniff_array.clear()

    t = threading.Thread(target=packet_producer, name='LoopThread')
    t.start()


# 将抓到的数据包保存为pcap格式的文件
def save_captured_data_to_file():
    try:
        save_time = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())
        fpath = "./capture_packages_" + save_time + ".pacp"
        wrpcap(fpath, sniff_array)
        #   stop_sniff_event.clear()
    except:
        print("Blank File,Please Try Another Interface Or waiting for longer time.")
        pass



# 停止按钮单击响应函数
def stop_capture():
    stop_sniff_event.set()


def quit_program():
    if sniff_count != 0:
        save_captured_data_to_file()
    exit(0)


# 获取网卡列表
interfaces_test = get_working_ifaces()
interfaces_temp = {}
for i in range(len(interfaces_test)):
    interfaces_temp[i] = interfaces_test[i].description
interfaces = [j for j in interfaces_temp.values()]
for j in range(len(interfaces)):
    print("[" + str(j+1) + "]  " + interfaces[j])
chosen = int(input('Choose One: '))-1
interface_chosen = interfaces[chosen]
start_capture()
while (1):
    quitcmd = input("Waiting:\n")
    if quitcmd == "quit":
        stop_capture()
        quit_program()
    else:
        continue
