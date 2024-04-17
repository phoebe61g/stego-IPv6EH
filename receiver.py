#!/usr/bin/python
import time
import socket
import dataop, fileop, pktop
import reedsolomon as rs
codec = rs.set_codec(255, 223)
# Packet Sniffer
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((str(conf.iface), 0))
print("Start sniffing...")
T_sniff = time.time() # Timer
frame_buff = pktop.sniff_ip6_DstEH(s)
s.close()
print("Done. Sniffed {} frames.".format(len(frame_buff)))
# Codeword Collection 
print("Start extracting data...")
T_extract = time.time() # Timer
filename, cw_cnt, last = dataop.extract_RR(frame_buff[0])
cw_list = dataop.extract_cw(frame_buff, cw_cnt)
print("Done.")
# RS Decoder
print("Start decoding data...")
T_decode = time.time() # Timer
data_list = []
for cw_index in range(cw_cnt):
    try:
        codeword = b''.join(cw_list[cw_index * 16:cw_index * 16 + 16]) 
        dec_data = rs.decoder(codeword, codec)
        # Data Collection
        data_list.append(dec_data)
    except:
        print("Codeword[{}] couldn't be decoded.".format(cw_index))
print("Done.")
# File Generator
print("Start generating the original file...")
T_file = time.time() # Timer
collect_data = fileop.bin_collect(data_list, cw_cnt, last)
fileop.generate(filename, collect_data)
T_end = time.time() # Timer
print("Done.")
print("------ Time Consuming ------")
print("Sniffing packets: {:.2f} seconds.".format(T_extract - T_sniff))
print("Extracting codeword: {:.2f} seconds.".format(T_decode - T_extract))
print("Decoding data: {:.2f} seconds.".format(T_file - T_decode))
print("Generating file: {:.2f} seconds.".format(T_end - T_file))
print("Totally spent {:.2f} seconds.".format(T_end - T_sniff))
exit()
