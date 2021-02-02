#!usr/bin/python
from scapy.all import sendp, rdpcap
#pkts = rdpcap("2018-12-27-shade-malspam-infection.pcap")
#pkts = rdpcap("t4.pcap")
pkts = rdpcap("skewness1.2.pcap")
for pkt in pkts:
	sendp(pkt,inter=1./600)

