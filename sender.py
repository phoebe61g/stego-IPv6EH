#!/usr/bin/python
import sys, time
import fileop, pktop
import reedsolomon as rs
from config import N, K, T, Timer

# File Reader
print("Reading file...")
T_reader = time.time()
filename = sys.argv[1]
data_list, padding = fileop.reader(filename, K)

# RS Encoder
print("Encoding...")
T_encoder = time.time()
cw_list = []
codec = rs.set_codec(N, K)
for chunk in data_list: 
    codeword = rs.encoder(chunk, codec) 
    # Codeword Slicer
    slice = [codeword[i:i+T] for i in range(0, len(codeword), N//T + 1)]
    cw_list.append(slice)

# Packet Generator
print("Generating & sending packets...")
T_generator = time.time()
cw_cnt = len(cw_list)
pktop.generate_send(filename, cw_list, cw_cnt, padding)
T_end = time.time()
print("Finished sending {} packets.".format(cw_cnt*16))

if Timer:
    print("------ Time Consuming ------")
    print("File Reader: {:.2f} seconds.".format(T_encoder - T_reader))
    print("RS Encoder & Codeword Slicer: {:.2f} seconds.".format(T_generator - T_encoder))
    print("Packets Generator: {:.2f} seconds.".format(T_end - T_generator))
    print("Totally spent {:.2f} seconds.".format(T_end - T_reader))
exit()
