#!/usr/bin/python
import sys, time
import fileop, pktop
import reedsolomon as rs
from config import N, K, T, Timer
codec = rs.set_codec(N, K)
# File Processor
print("Start slicing data...")
T_slice = time.time() # Timer
filename = sys.argv[1]
<<<<<<< HEAD
data_list, padding = fileop.reader(filename, K)
print("Done.")
# RS Encoder
cw_list = []
print("Start encoding...")
T_encode = time.time() # Timer
for chunk in data_list: 
    codeword = rs.encoder(chunk, codec) 
=======
data_list, last = fileop.bin_split(filename)
print("Done.")
# RS Encoder
cw_list = []
data_cnt = len(data_list)
print("Start encoding...")
T_encode = time.time() # Timer
for i in range(data_cnt): 
    codeword = rs.encoder(data_list[i], codec) 
>>>>>>> 02c986ef7d8243a473b2f9f9826dcf0dd9d09eea
    # Codeword Slicing
    cw_slice = [codeword[i:i+16] for i in range(0, len(codeword), 16)]
    cw_list.append(cw_slice)
print("Done.")
# Packet Generator
print("Start generating & sending packets...")
T_send = time.time() # Timer
cw_cnt = len(cw_list)
pktop.generate_send(filename, cw_list, cw_cnt, padding)
T_end = time.time() # Timer
print("\nDone.")
print("Finished sending {} packets.".format(cw_cnt*16))
print("------ Time Consuming ------")
print("Processing file: {:.2f} seconds.".format(T_encode - T_slice))
print("Encoding data: {:.2f} seconds.".format(T_send - T_encode))
print("Sending packets: {:.2f} seconds.".format(T_end - T_send))
print("Totally spent {:.2f} seconds.".format(T_end - T_slice))
exit()
