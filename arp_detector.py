import scapy.all as scapy
ip_mac_map = {}

def process(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        ip = packet[scapy.ARP].psrc
        mac = packet[scapy.ARP].hwsrc

        if ip in ip_mac_map:
            if ip_mac_map[ip] != mac:
                print(f"[!!!] ALERT: Possible ARP spoofing!")
                print(f"      {ip} was {ip_mac_map[ip]}, now claims {mac}")
        else:
            ip_mac_map[ip] = mac
            print(f"[*] Learned: {ip} is at {mac}")

print("[*] ARP spoofing detector running... (Ctrl+C to stop)")
scapy.sniff(filter="arp", store=0, prn=process)
