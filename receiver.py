#!/usr/bin/python
import sys
import time
import socket
from scapy.all import *
# Sniff the packets
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(('ens160', 0))
frame_buff = []
timelimit = int(sys.argv[1])
start = time.time() # Timer
print("Start sniffing...")
while (time.time() - start) < timelimit: 
    frame, addr = s.recvfrom(512)
    if frame[12:14] == b'\x86\xdd': # Filter for IPv6
        frame_buff.append(frame)
s.close()
print("Stop sniffing. Start collecting data...")
# Collect if they're DNS packets
timestamp = time.time()
pkts_buff = []
for frame in frame_buff:
    pkt = Ether(frame) # Normalize to Scapy packet format
    try:
        if pkt.getlayer(UDP).dport == 53:
            pkts_buff.append(pkt)
    except:
        pass
if pkts_buff:
    pktl = PacketList(pkts_buff)
else:
    exit() # No special packets received
print(pktl.summary)
# Extract the data from packets
filename = ""
collect_data = b''
data_buff = {}
error_cnt = 0
for pkt in pktl:
    try:
        padn = pkt.getlayer(IPv6ExtHdrDestOpt).options[0]
        data = padn.optdata
        dnsID = pkt.getlayer(DNS).id
        if dnsID == 0:
            filename = data
        else:
            data_buff[dnsID - 1] = data
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
