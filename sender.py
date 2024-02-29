#!/usr/bin/python
import sys
import time
from scapy.all import *
import getinfo, fileop
import reedsolomon as rs
codec = rs.set_codec(255, 223)
dnsMAC, dnsIP = getinfo.dst_addrs()
# Process the binary file to send
print("Start slicing data...")
T_slice = time.time() # Timer
filename = sys.argv[1]
msglist, cw_cnt, last = fileop.bin_split(filename)
cwlist = []
# RS(255,223) Encoder
print("Start encoding...")
T_encode = time.time()
for i in range(cw_cnt): 
    encmsg = rs.encoder(msglist[i], codec) # Encode 223-bytes into 255-bytes codeword.
    cw_slicing = [encmsg[i:i+16] for i in range(0, len(encmsg), 16)]
    cwlist.append(cw_slicing)
# Send
print("Start sending...")
T_send = time.time()
whohas_pre = filename + '.' + str(cw_cnt) + '.'
print("--> <filename>.<codeword_cnt>.<codeword_index>.<last_bytes>.org")
for cw in range(cw_cnt):
    for i in range(16):
        whohas = whohas_pre + str(cw) + '.' + str(last) + '.org'
        pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(optdata=cwlist[cw][i]))/UDP(dport=53)/DNS(id=i, qd=DNSQR(qname=whohas, qtype="A"))
        send(pkt, verbose=0)
        print("Packets sended: index {}".format(cw * 16 + i), end = '\r')
        #time.sleep(0.005)
T_end = time.time() # Timer
print("\nFinished sending {} packets.".format(cw_cnt * 16))
print("Time for slicing: {:.2f} seconds.".format(T_encode - T_slice))
print("Time for encoding: {:.2f} seconds.".format(T_send - T_encode))
print("Time for sending: {:.2f} seconds.".format(T_end - T_send))
print("Totally spent {:.2f} seconds.".format(T_end - T_slice))
exit()
