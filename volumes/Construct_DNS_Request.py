from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP


def send_dns_request():
    Qdsec = DNSQR(qname="abcde.example.com")    # abcde - placeholder for random subdomain
    dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,arcount=0, qd=Qdsec)
    ip = IP(dst="10.9.0.53", src = "10.9.0.1") # dst is the local DNS server, src is the attacker
    udp = UDP(dport=53, sport=RandShort(), chksum=0) # dport is the DNS port - 53
    request = ip/udp/dns
    
    # Save the request to a binary file
    with open("ip_req.bin", "wb") as file:
        file.write(bytes(request))

if __name__ == "__main__":
    send_dns_request()
