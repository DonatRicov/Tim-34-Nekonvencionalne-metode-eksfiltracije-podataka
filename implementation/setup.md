# DNS Tunneling

## 1. Zahtjevi

Prije pokretanja projekta potrebno je imati:

* Linux Mint ili Ubuntu (preporučeno unutar VirtualBoxa)
* Python 3.10 ili noviji
* Administratorski (sudo) pristup sustavu
* Instalirane potrebne pakete:
```
  * `python3-dnslib`
  * `python3-dnspython`
  * `tcpdump`
  * `wireshark`
```

## 2. Instalacija ovisnosti

### Ažuriranje paketa
```
sudo apt update
```
### Instalacija Python biblioteka preko APT-a
```
sudo apt install -y python3-dnslib python3-dnspython
```
### Instalacija mrežnih alata
```
sudo apt install -y tcpdump wireshark
```
## 3. Kloniranje repozitorija
```
git clone https://github.com/<korisničko-ime>/<repozitorij>.git
cd <repozitorij>
```
## 4. Pokretanje DNS tunela

### Korak 1 — Pokretanje tcpdump nadzora

U posebnom terminalu pokrenite:
```
sudo tcpdump -i lo udp port 5354 -w dns_capture.pcap
```
Ovo će snimiti sav DNS promet na lokalnom portu 5354, za kasniju analizu u Wiresharku.

### Korak 2 — Pokretanje DNS poslužitelja

U novom terminalu:
```
python3 dns_server.py
```
Ako sve radi ispravno, trebali biste vidjeti:
```
Starting DNS server on 0.0.0.0:5354
```

### Korak 3 — Slanje skrivene poruke iz klijenta
```
python3 client.py
```
Očekivani ispis:
```
Sent DNS tunnel message 'Sutra kava u 12:00.' ...
Received response:
<dns.message.Message ...>
```
U terminalu poslužitelja trebala bi se pojaviti dekodirana poruka:
```
Extracted secret message: Sutra kava u 12:00.
```
## 5. Analiza prometa u Wiresharku

1. Zaustavite `tcpdump` pritiskom Ctrl + C.
2. Otvorite datoteku u Wiresharku:
```
wireshark dns_capture.pcap
```
3. U filter upišite:
```
dns
```
4. U DNS Query Name polju vidjet ćete Base64-kodiranu poruku kao poddomenu domene `eksfiltracija.hr`.

Time se potvrđuje uspješan DNS tunneling i eksfiltracija podataka.
