#!/usr/bin/python
import sys, time
import fileop, pktop
import reedsolomon as rs
from config import N, K, T, Timer
codec = rs.set_codec(N, K)
# File Reader
T_reader = time.time()
print("Reading file...")
filename = sys.argv[1]
data_list, padding = fileop.reader(filename, K)

# RS Encoder
T_encoder = time.time()
print("Encoding...")
cw_list = []
for chunk in data_list: 
    codeword = rs.encoder(chunk, codec) 
    # Codeword Slicer
    cw_slice = [codeword[i:i+16] for i in range(0, len(codeword), 16)]
    cw_list.append(cw_slice)

# Packet Generator
print("Generating & sending packets...")
T_generator = time.time()
cw_cnt = len(cw_list)
pktop.generate_send(filename, cw_list, cw_cnt, padding)
T_end = time.time()
print("Finished sending {} packets.".format(cw_cnt*16))

if Timer:
    print("------ Time Consuming ------")
    print("Processing file: {:.2f} seconds.".format(T_encoder - T_reader))
    print("Encoding data: {:.2f} seconds.".format(T_generator - T_encoder))
    print("Sending packets: {:.2f} seconds.".format(T_end - T_generator))
    print("Totally spent {:.2f} seconds.".format(T_end - T_reader))
exit()
