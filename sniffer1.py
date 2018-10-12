from scapy.all import *

def showPacket(packet):
	a = packet.show()
	print a

def sniffing(filter):
	sniff(filter = filter, prn = showPacket, count = 1)

if __name__ == '__main__':
	ip="192.168.0.7"
	filter = ip
	sniffing(filter)
