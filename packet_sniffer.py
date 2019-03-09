import scapy.all as scapy

def sniff(inferface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    print(packet)

sniff("eth0")
