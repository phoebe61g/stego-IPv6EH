#!/usr/bin/python
import sys
import time
import socket
from scapy.all import *
import sniffer
import dataop
import reedsolomon as rs
codec = rs.set_codec(255, 223)
# Sniff the packets
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((str(conf.iface), 0))
print("Start sniffing...")
T_sniff = time.time() # Timer
frame_buff = sniffer.sniff_ip6_DstEH(s)
s.close()
# Extract the data from packets
print("Start extracting data...")
T_extract = time.time()
pkts_buff = dataop.convert_frame_pkt(frame_buff)
pktl = PacketList(pkts_buff)
print(pktl.summary)
filename, cw_cnt, last = dataop.extract_RR(pktl[0])
encdata_buff = dataop.extract_data(pktl, cw_cnt)
#dataop.find_missing_cw(encdata_buff)
# Decoding
print("Start decoding data...")
T_decode = time.time()
decdata = []
for cw_index in range(cw_cnt):
    try:
        codeword = b''.join(encdata_buff[cw_index * 16:cw_index * 16 + 16]) # 255-bytes
        decdata.append(rs.decoder(codeword, codec))
    except:
        print("Codeword[{}] couldn't be decoded.".format(cw_index))
        print("Size: {}".format(len(codeword)))
# Combine data and write into a binary file
print("Start generating the org file...")
T_file = time.time()
collect_data = b''
for i in range(cw_cnt - 1):
        collect_data = collect_data + decdata[i]
collect_data = collect_data + decdata[cw_cnt - 1][:last]
rebuild = open(filename, 'wb+')
rebuild.write(collect_data)
rebuild.close()
print("Finished.")
T_end = time.time()
print("Time for sniffing: {:.2f} seconds.".format(T_extract - T_sniff))
print("Time for extracting: {:.2f} seconds.".format(T_decode - T_extract))
print("Time for decoding: {:.2f} seconds.".format(T_file - T_decode))
print("Time for rebuilding file: {:.2f} seconds.".format(T_end - T_file))
print("Totally spent {:.2f} seconds.".format(T_end - T_sniff))
exit()
