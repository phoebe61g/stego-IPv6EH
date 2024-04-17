#!/usr/bin/python
import sys, time
import fileop, pktop
import reedsolomon as rs
codec = rs.set_codec(255, 223)
# File Processor
print("Start slicing data...")
T_slice = time.time() # Timer
filename = sys.argv[1]
data_list, last = fileop.bin_split(filename)
print("Done.")
# RS Encoder
cw_list = []
data_cnt = len(data_list)
print("Start encoding...")
T_encode = time.time() # Timer
for i in range(data_cnt): 
    codeword = rs.encoder(data_list[i], codec) 
    # Codeword Slicing
    cw_slice = [codeword[i:i+16] for i in range(0, len(codeword), 16)]
    cw_list.append(cw_slice)
print("Done.")
# Packet Generator
print("Start generating & sending packets...")
T_send = time.time() # Timer
pktop.generate_send(filename, cw_list, data_cnt, last)
T_end = time.time() # Timer
print("\nDone.")
print("Finished sending {} packets.".format(data_cnt*16))
print("------ Time Consuming ------")
print("Processing file: {:.2f} seconds.".format(T_encode - T_slice))
print("Encoding data: {:.2f} seconds.".format(T_send - T_encode))
print("Sending packets: {:.2f} seconds.".format(T_end - T_send))
print("Totally spent {:.2f} seconds.".format(T_end - T_slice))
exit()
