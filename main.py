from scapy.all import *
print(conf.ifaces)

sniff(count=5, prn=lambda x: x.summary())