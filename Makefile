RUN = sudo python3 main.py -i any -c 1 -f
IP = google.com

arp:
	$(RUN) arp

udp:
	$(RUN) udp

tcp:
	$(RUN) tcp

icmp:
	$(RUN) icmp

dns:
	$(RUN) dns

p-arp:
	arping -c 1 $(IP)

p-udp:
	echo "Hello, World!" | ncat --udp 192.168.0.1 12345

p-tcp:
	curl http://$(IP)

p-icmp:
	ping -c 1 $(IP)

p-dns:
	nslookup $(IP) -retry=10
