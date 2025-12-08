# Zapažanja

Tijekom istraživanja i praktične implementacije nekonvencionalnih tehnika eksfiltracije podataka analizirane su četiri metode: DNS tunneling, covert timing channels, steganografija i SMTP abuse. Svaka tehnika evaluirana je prema vidljivosti, propusnosti, stabilnosti te detektabilnosti u realnom mrežnom okruženju.

## 1. DNS tunneling

- DNS se pokazao kao izuzetno pogodan kanal zbog toga što je gotovo uvijek dozvoljen prema internetu i prolazi kroz većinu firewall konfiguracija.

- Propusnost je bila ograničena i značajno varira ovisno o veličini DNS paketa te latenciji mreže.

- Iako je tehnika funkcionalna, generira neuobičajene DNS obrasce (velike ili neobične nazive domena), što se može relativno lako detektirati naprednijim IDS/IPS sustavima ili ML-based DNS analizama.

- Upadljivo povećan broj DNS upita prema jednoj domeni bio je indikator koji bi u praksi privukao pozornost.

## 2. Steganografija

- Skriveni sadržaj uspješno je umetnut u sve testirane .png slike, bez vidljivih promjena u njihovom vizualnom prikazu. LSB metoda pokazala se stabilnom, a umetnuti podaci (tekst, tekstualne datoteke datoteke, zvučni zapis) bili su u potpunosti rekonstruirani bez gubitka integriteta.

- .jpg format pokazao se nepouzdanim za LSB steganografiju. Tijekom testiranja Stegano je morao pretvoriti .jpg sliku u .png, što je uzrokovalo značajno povećanje veličine datoteke i potvrdilo teorijsko ograničenje *lossy* kompresije pri manipulaciji najmanje značajnih bitova.

- Promjena veličine .png datoteka nakon umetanja bila je minimalna, obično u rasponu od nekoliko desetaka kilobajta, što ukazuje da LSB metoda zahvaća samo bitove koji ne utječu na vizualnu kvalitetu slike.
  
- Kodiranje u Base64, umetanje sadržaja i naknadno izdvajanje obavljalo se pravilno, a rezultirajuće datoteke bile su identične izvornima. Automatizacija je uklonila mogućnost ljudske pogreške i standardizirala postupak.

- Vizualno, .png slike prije i nakon umetanja ostale su nepromijenjene. Potrebno je naglasiti da specijalizirani alati za stegoanalizu mogu otkriti nepravilnosti u distribuciji LSB bitova, osobito kod većih ugrađenih datoteka.

## 3. Covert timing channels

- Kodiranje podataka vremenskim razmacima između paketa (inter-packet delay) funkcioniralo je, ali je jako osjetljivo na vanjske faktore poput jittera i fluktuacija u mrežnom prometu.

- Testovi između virtualnih mašina (VM-ova) u kontroliranom okruženju pokazali su stabilnije rezultate nego u stvarnim mrežnim uvjetima.

- Upotreba jednostavnih skripti u Pythonu omogućila je simulaciju i dekodiranje uzoraka.

- Ova metoda ima izuzetno malu propusnost.

- Neregularni vremenski obrasci, iako suptilni, mogu biti detektirani sustavima koji analiziraju statističke anomalije u prometu.

- Potencijalna stopa grešaka raste s opterećenjem mreže.

## 4. SMTP abuse

- Eksfiltracija pokazala se vrlo jednostavnom i stabilnom.

- Poruke mogu izgledati kao legitimna komunikacija, što smanjuje potencijalnu sumnju.

- SMTP kao protokol prirodno podržava prijenos većih količina podataka.

- Iako je ova metoda funkcionalna, lako je otkriti anomalije u mail logovima.

- DLP sustavi često nadziru izlazni e-mail promet i mogu spriječiti izlaz podataka.
