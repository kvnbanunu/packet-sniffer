RUN = sudo python3 main.py -i any -c 1 -f
IP = 192.168.0.72

arp:
	$(RUN) arp

udp:
	$(RUN) udp

tcp:
	$(RUN) tcp

icmp:
	$(RUN) icmp

p-arp:
	arping -c 1 $(IP)

p-udp:
	echo "Hello, World!" | ncat --udp 192.168.0.1 12345

p-tcp:
	curl http://$(IP)

p-icmp:
	ping -c 1 $(IP)

