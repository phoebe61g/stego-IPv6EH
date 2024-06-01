#!/usr/bin/python
import time
import socket
import dataop, fileop, pktop
import reedsolomon as rs
from config import N, K, T, Timer
codec = rs.set_codec(N, K)

# Packet Collector
T_collector = time.time()
print("Sniffing...")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((str(conf.iface), 0))
frame_buff = pktop.sniff_ip6_DstEH(s)
s.close()
print("---> Sniffed {} frames.".format(len(frame_buff)))

# Codeword Extraction
print("Extracting codewords...")
filename, cw_cnt, pad_bytes = dataop.extract_RR(frame_buff[0])
cw_list = dataop.extract_cw(frame_buff, cw_cnt)

# RS Decoder & File Composer
print("Decoding...")
T_decoder = time.time() 
bin_file = open(filename, 'wb+')
for chunk_num in range(cw_cnt):
    try:
        count = N//T + 1
        codeword = b''.join(cw_list[chunk_num * count:chunk_num * count + count]) 
        chunk = rs.decoder(codeword, codec)
        if chunk_num == (cw_cnt - 1):
            chunk = chunk[:K - pad_bytes]
        bin_file.write(chunk)
    except:
        print("Codeword[{}] couldn't be decoded.".format(chunk_num))
bin_file.close()
#fileop.del_padding(filename, pad_bytes)
T_end = time.time()
print("Done.")

if Timer:
    print("------ Time Consuming ------")
    print("Packet Collector: {:.2f} seconds.".format(T_decoder - T_collector))
    print("RS Decoder & File Composer: {:.2f} seconds.".format(T_end - T_decoder))
    print("Totally spent {:.2f} seconds.".format(T_end - T_collector))
exit()
