#!/usr/bin/python
import sys
import time
import socket
from scapy.all import *
import sniffer
# Sniff the packets
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((str(conf.iface), 0))
timelimit = int(sys.argv[1])
start = time.time() # Timer
print("Start sniffing...")
frame_buff = sniffer.sniff_ip6(s, start, timelimit)
#pkts_buff = sniffer.sniff_ip6_dns(s, start, timelimit)
s.close()
print("Stop sniffing. Start collecting data...")
# Collect if they're DNS packets
timestamp = time.time()
pkts_buff = sniffer.filter_dns(frame_buff)
if pkts_buff:
    pktl = PacketList(pkts_buff)
else:
    exit() # No special packets received
print(pktl.summary)
# Extract the data from packets
RR = pktl[0].getlayer(DNS).qd.qname.split(b'.')
filename = RR[0] + b'.' + RR[1]
print(filename)
collect_data = b''
data_buff = {}
error_cnt = 0
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
    try:
        collect_data = collect_data + data_buff[i]
    except:
        #print("Error happened while processing packet no.{}".format(i))
        error_cnt = error_cnt + 1
stop = time.time()
print("Time for collection: {:.2f} seconds.".format(stop - timestamp))
print("Lost {} data from packets. Start building file...".format(error_cnt))
rebuild = open(filename, 'wb+')
rebuild.write(collect_data)
rebuild.close()
print("Finished.")
