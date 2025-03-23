from scapy.all import sniff, DNSQR

def packet_callback(packet):
    if packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname.decode('utf-8')
        print(f"DNS Question Record: {qname}")

def main():
    # Sniff packets on the default interface
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()