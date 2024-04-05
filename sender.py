#!/usr/bin/python
import sys
import time
from scapy.all import *
import fileop, sendop
import reedsolomon as rs
codec = rs.set_codec(255, 223)
# Process the binary file to send
print("Start slicing data...")
T_slice = time.time() # Timer
filename = sys.argv[1]
msglist, cw_cnt, last = fileop.bin_split(filename)
# RS(255,223) Encoder
cwlist = []
print("Start encoding...")
T_encode = time.time()
for i in range(cw_cnt): 
    encmsg = rs.encoder(msglist[i], codec) # Encode 223-bytes into 255-bytes codeword.
    cw_slicing = [encmsg[i:i+16] for i in range(0, len(encmsg), 16)]
    cwlist.append(cw_slicing)
# Send
print("Start sending...")
T_send = time.time()
total = sendop.complete_send(filename, cwlist, cw_cnt, last)
#total = sendop.pkt_loss_send(filename, cwlist, cw_cnt, last)
T_end = time.time() # Timer
print("\nFinished sending {} packets.".format(total))
print("Time for slicing: {:.2f} seconds.".format(T_encode - T_slice))
print("Time for encoding: {:.2f} seconds.".format(T_send - T_encode))
print("Time for sending: {:.2f} seconds.".format(T_end - T_send))
print("Totally spent {:.2f} seconds.".format(T_end - T_slice))
exit()
