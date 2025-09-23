RUN = sudo python3 main.py -i any -c 1 -f
IP = google.com

arp:
	$(RUN) arp

udp:
	$(RUN) udp

tcp:
	$(RUN) tcp

udp6:
	$(RUN) 'ip6 and udp'

tcp6:
	$(RUN) 'ip6 and tcp'

icmp:
	$(RUN) icmp

icmp6:
	$(RUN) icmp6

ip6:
	$(RUN) ip6

dns:
	$(RUN) 'udp port 53 or tcp port 53'

p-arp:
	sudo arping -c 1 $(IP)

p-udp:
	echo "Hello, World!" | ncat --udp 192.168.0.1 12345

p-tcp:
	curl http://$(IP)

p-icmp:
	ping -c 1 $(IP)

p-ip6:
	ping ff02::1%wlan0

p-dns:
	nslookup $(IP) -retry=10
