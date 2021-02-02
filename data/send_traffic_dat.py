#!usr/bin/python
from scapy.all import *

"""test
f = open("1.dat")
byt = f.read(13)
for _ in range(len(byt)):
	src_ip = ".".join(map(str,(ord(byt[i]) for i in range(4))))
	src_port = str((ord(byt[4]))*256 + ord(byt[5]))
	print src_ip
	print src_port
f.close
"""

def read_file(filePath,chunk_size=13):
	file_object = open(filePath)
	s = conf.L3socket(iface='eth0')
	while True:
		#chunk_data is 13 byte, src_ip\src_port\dst_ip\dst_port\protocol
		chunk_data = file_object.read(chunk_size)
		if not chunk_data:
			break
		else:
			src_ip = ".".join(map(str,(ord(chunk_data[i]) for i in range(0,3))))
			src_port = str(( ord(chunk_data[4]))*256 + ord(chunk_data[5]) )
			dst_ip = ".".join(map(str,(ord(chunk_data[i]) for i in range(6,9))))
			dst_port = str( (ord(chunk_data[10]))*256 + ord(chunk_data[11]))
#			print src_ip
#			print src_port
#			print dst_ip
#			print dst_port		
			s.send(IP(dst=dst_ip,src=src_ip))
			print "**********************"
if __name__ == "__main__":
	filePath = "1.dat"
	read_file(filePath)
