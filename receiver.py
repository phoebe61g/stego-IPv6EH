#!/usr/bin/python
import sys
import time
import socket
from scapy.all import *
import sniffer
# Sniff the packets
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((str(conf.iface), 0))
#timelimit = int(sys.argv[1])
start = time.time() # Timer
print("Start sniffing...")
filename, pkts_buff = sniffer.sniff_cnt_ip6_dns(s)
#frame_buff = sniffer.sniff_ip6(s, start, timelimit)
s.close()
timestamp = time.time()
print("Time for sniffing: {:.2f} seconds.".format(timestamp - start))
#pkts_buff = sniffer.filter_dns(frame_buff)
print("Filename: {}".format(filename))
pktl = PacketList(pkts_buff)
print(pktl.summary)
# Extract the data from packets
print("Start collecting data...")
collect_data = b''
data_buff = {}
for pkt in pktl:
    try:
        padn = pkt.getlayer(IPv6ExtHdrDestOpt).options[0]
        data = padn.optdata
        dnsID = pkt.getlayer(DNS).id
        data_buff[dnsID] = data
    except:
        pass
# Combine data into a binary file
for i in range(0, len(data_buff)):
    collect_data = collect_data + data_buff[i]
stop = time.time()
print("Time for collection: {:.2f} seconds.".format(stop - timestamp))
rebuild = open(filename, 'wb+')
rebuild.write(collect_data)
rebuild.close()
print("Finished.")
exit()
