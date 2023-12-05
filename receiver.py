#!/usr/bin/python
import sys
import time
import socket
from scapy.all import *
import sniffer
import reedsolomon as rs
codec = rs.set_codec(255, 223)
# Sniff the packets
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((str(conf.iface), 0))
print("Start sniffing...")
T_sniff = time.time() # Timer
filename, cw_cnt, pkts_buff, redun = sniffer.sniff_cnt_ip6_dns(s)
s.close()
# Extract the data from packets
print("Start extracting data...")
T_extract = time.time()
pktl = PacketList(pkts_buff)
print(pktl.summary)
encdata_buff = [b'0'] * 255 * cw_cnt
for pkt in pktl:
    try:
        padn = pkt.getlayer(IPv6ExtHdrDestOpt).options[0]
        data = padn.optdata
        RR = pkt.getlayer(DNS).qd.qname.split(b'.')
        dnsID = pkt.getlayer(DNS).id
        index = int(RR[3]) * 16 + dnsID
        encdata_buff[index] = data
    except:
        pass
# Decoding
print("Start decoding data...")
T_decode = time.time()
decdata = []
for cw in range(cw_cnt):
    codeword = b''.join(encdata_buff[cw*16:cw*16+16])
    decdata.append(rs.decoder(codeword, codec))
# Combine data and write into a binary file
print("Start generating the org file...")
T_file = time.time()
collect_data = b''
for i in range(cw_cnt - 1):
        collect_data = collect_data + decdata[i]
collect_data = collect_data + decdata[cw_cnt - 1][:redun]
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
