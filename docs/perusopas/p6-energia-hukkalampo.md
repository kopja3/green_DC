# P6 – Energian kulutus ja hukkalämmön hyödyntäminen

Tavoite: syventää M5-moduulin sisältöä ja selittää, mistä datakeskuksen kilowattitunnit syntyvät, miten ne jakautuvat eri komponenttien kesken ja miten tämä näkyy hiilidioksidipäästöissä sekä hukkalämmön hyödyntämisen potentiaalissa.

## P6.1 Energiankulutuksen jakautuminen datakeskuksessa

Datakeskuksessa kulutettu sähköenergia jakautuu useiden komponenttien kesken. Suurimman osan energiasta kuluttavat palvelimet, mutta merkittäviä osuuksia käyttävät myös jäähdytysjärjestelmät, verkkolaitteet ja sähkönsyötön apujärjestelmät (UPS, PDU, muuntajat jne.).

Palvelimet käyttävät yleisesti noin **50–70 %** datakeskuksessa käytettävästä sähköenergiasta, sisältäen prosessorit, muistit ja virtalähteiden häviöt [4]. Loput energiasta jakautuu pääasiassa jäähdytysjärjestelmien, verkkolaitteiden ja UPS-järjestelmien kesken.

### P6.1.1 Prosessorit (CPU)

Prosessorit muodostavat merkittävän osan palvelimen sähkönkulutuksesta. Yksittäinen prosessori kuluttaa työkuormasta riippuen noin **45–200 W**, ja niiden osuus palvelimen kokonaistehonkulutuksesta on tyypillisesti **25–40 %** [5].  

Mitä raskaampia laskentatehtäviä (esim. tekoälymallit, tietokantakyselyt) suoritetaan, sitä suurempi osuus energiasta kohdistuu prosessoreihin.

### P6.1.2 Muisti (RAM)

Muisti kuluttaa tyypillisesti noin **20–30 %** palvelimen sähkötehosta [5]. Kulutukseen vaikuttavat:

- muistikanavien määrä  
- muistimoduulien kapasiteetti  
- työkuormien muistivaatimukset sekä moniydinprosessorien käyttö.

Muistia paljon käyttävät sovellukset (esim. in-memory-tietokannat) voivat kasvattaa merkittävästi palvelimen kokonaisenergiankulutusta.

### P6.1.3 Virtalähteet (PSU)

Virtalähteiden (PSU, Power Supply Unit) osuus palvelimen kokonaisenergiasta on tyypillisesti **10–20 %** [6].  

Virtalähteen hyötysuhdetta parantaa muun muassa **Power Factor Correction (PFC)**, joka vähentää loistehoa ja energiahävikkiä. Hyötysuhteeltaan korkeammat virtalähteet (esim. 80 PLUS -sertifioidut) tukevat parempaa kokonaisenergiatehokkuutta.

### P6.1.4 Verkkolaitteet

Verkkolaitteet, kuten reitittimet ja kytkimet, käyttävät arviolta noin **8 %** datakeskuksen sähköenergiasta, mikä suurissa keskuksissa voi vastata jopa **0,8 MW** tehoa [5].  

Erityisesti runkoverkossa käytettävät korkean kapasiteetin laitteet (10–400 Gbit/s portit) kuluttavat paljon energiaa, minkä vuoksi niiden valinnassa ja konfiguroinnissa kannattaa huomioida energiatehokkuusominaisuudet.

### P6.1.5 Tehonhallinta ja UPS-järjestelmät

Tehonhallintayksiköt ja UPS-järjestelmät kuluttavat yleensä noin **10–12 %** datakeskuksen energiasta [6].  

Vaikka UPS-järjestelmät ovat välttämättömiä sähkönsyötön varmistamiseksi, niiden häviöt kasvattavat kokonaiskulutusta. Siksi:

- UPS-järjestelmät mitoitetaan oikean kokoisiksi  
- hyötysuhteeltaan korkeita ratkaisuja suositaan  
- toimintaa seurataan jatkuvasti mittaustietojen avulla.

## P6.2 Jäähdytyksen energiankulutus ja suhteellinen osuus

Jäähdytysjärjestelmät ovat toinen suuri energiankuluttaja datakeskuksessa. Tyypillisesti:

- **jäähdytysjärjestelmät** (esim. CRAC-yksiköt, pumput, puhaltimet) käyttävät noin **30–40 %** koko datakeskuksen energiasta [4, 5].

Jäähdytyksen energiankulutusta voidaan pienentää esimerkiksi:

- hyödyntämällä **vapaajäähdytystä**, kun ulkolämpötila on riittävän matala  
- käyttämällä **korkean hyötysuhteen** jäähdytyslaitteita  
- optimoimalla **ilmavirtoja** (hot/cold aisle) ja lämpötilan asetusarvoja  
- ottamalla käyttöön **nestejäähdytys** suuritehoisille palvelimille.

Jäähdytyksen suhteellinen osuus näkyy suoraan PUE-luvussa: mitä vähemmän energiaa kuluu jäähdytykseen suhteessa IT-kuormaan, sitä lähempänä PUE-arvo on 1,0.

## P6.3 Energia, kWh ja päästöt (perusfysiikka)

Energia määritellään työn kautta. Energiankansainvälinen SI-yksikkö on **joule (J)**, ja sähköenergian yleinen yksikkö on **kilowattitunti (kWh)**.  

Yksi kilowattitunti vastaa **3,6 megajoulea**. Kilowattitunti lasketaan kertomalla sähkölaitteen teho (kilowatteina, kW) sillä ajalla, jonka laite on ollut käytössä (tunteina, h):

> **kWh = teho (kW) × käyttöaika (h)**

Datakeskuksen tapauksessa:

- jos IT-kuorma on keskimäärin 500 kW ja sitä ajetaan 24 h vuorokaudessa, energiankulutus on  
  500 kW × 24 h = 12 000 kWh / vrk.

Hiilidioksidipäästöjen arvioinnissa käytetään **päästöintensiteettiä**, joka ilmoittaa kuinka paljon CO₂-päästöjä syntyy yhtä kWh:ta kohti (esim. gCO₂/kWh tai kgCO₂/kWh).  

Päästöarvio saadaan:

> **CO₂-päästöt = energian kulutus (kWh) × päästöintensiteetti (kgCO₂/kWh)**

## P6.4 Miksi datakeskus aiheuttaa hiilidioksidipäästöjä

Hiilidioksidipäästöjen määrä riippuu datakeskuksen kuluttamasta sähköenergiasta ja siitä, miten sähkö tuotetaan. Datakeskukset toimivat ympäri vuorokauden ja vaativat jatkuvan energiantuotannon, mikä lisää sähkön kulutusta ja edelleen hiilidioksidipäästöjä, jos energialähteet eivät ole uusiutuvia.

Suuri määrä palvelimia, jäähdytysjärjestelmiä ja muita infrastruktuurilaitteita vaatii jatkuvaa sähköä toimiakseen. Jos sähkö tuotetaan fossiilisilla polttoaineilla, kuten kivihiilellä, maakaasulla tai öljyllä, syntyy merkittävästi hiilidioksidipäästöjä (Kuva 3).

*Kuva 3. Hiilivoimala aiheuttaa merkittäviä hiilidioksidipäästöjä (vasemmalla), kun taas aurinko-, tuuli- ja vesivoimalat tuottavat sähköenergiaa vähäisin päästöin (oikealla).*

Suomen sähköenergiasta tuotetaan ydinvoimalla noin 30 %. Uusiutuvista energialähteistä tuulivoiman osuus kasvaa jatkuvasti, ja sen arvioidaan tuottavan jopa 50 % maan sähköstä vuoteen 2030 mennessä. Myös aurinkoenergiaa käytetään kasvavassa määrin, mutta sen osuus on edelleen verrattain pieni. Fossiiliset polttoaineet ja maakaasu ovat pienentyvä osa Suomen sähköntuotantoa, mutta niitä käytetään edelleen erityisesti kulutushuippujen aikana [2, 3].

Useissa datakeskuksissa on varavoimajärjestelmiä, kuten dieselgeneraattoreita, jotka aktivoituvat sähkökatkon sattuessa. Näiden käyttö aiheuttaa lisäpäästöjä erityisesti huoltokatkosten ja hätätilanteiden aikana. Jatkuvan sähkönsyötön varmistamiseksi tarvitaan energian varastointijärjestelmiä, jotka voivat tasata uusiutuvien energianlähteiden vaihtelevaa saatavuutta. Akut ja muut energian varastointitekniikat, kuten pumppuvoimalaitokset ja lämpövarastot, ovat keinoja varmistaa, että energiaa on saatavilla myös silloin, kun esimerkiksi aurinko ei paista tai tuuli ei puhalla [13].  

Vihreissä datakeskuksissa hyödynnetään mahdollisimman paljon uusiutuvia energialähteitä, kuten aurinkoa, tuulta tai vesivoimaa. Tämä vähentää riippuvuutta fossiilisista polttoaineista ja tukee hiilidioksidipäästöjen vähentämistä [5, 12].

## P6.5 Vihreä datakeskus ja energiatehokkuus

Vihreät datakeskukset suunnitellaan kuluttamaan mahdollisimman vähän energiaa käyttämällä energiatehokkaita laitteisto- ja ohjelmistoratkaisuja. Tähän kuuluvat:

- korkean hyötysuhteen laitteet (palvelimet, UPS-laitteet, pumput, puhaltimet)  
- kuormanhallinta ja sähkönsyötön optimointi  
- älykäs sähkönjakelu ja uusiutuvan energian yhdistäminen energian varastointijärjestelmiin [10].

Vihreä datakeskus edistää IT-infrastruktuurin ja laskentakapasiteetin energiatehokasta ja ympäristöystävällistä hyödyntämistä käyttämällä uusiutuvia energialähteitä ja vähentämällä energiankulutusta. Tämä saavutetaan energiatehokkaiden laitteiden, älykkäiden jäähdytysratkaisujen ja kierrätysmenetelmien avulla sekä noudattamalla kestävän kehityksen periaatteita koko datakeskuksen elinkaaren ajan [4].

Virtuaalisointi on tärkeä osa energiatehokkuutta: fyysisten palvelimien energiatehokkuutta parannetaan, ja yhä enemmän käytetään virtuaalipalvelimia, jotka mahdollistavat useiden työkuormien ajamisen samalla fyysisellä laitteistolla. Tämä vähentää fyysisten palvelimien määrää, säästää energiaa ja tilaa sekä pienentää jäähdytystarvetta [16].

Modulaarinen suunnittelu mahdollistaa datakeskuksen joustavan laajentamisen tai supistamisen ilman tarpeetonta resurssien hukkaa. Kestävä suunnittelu keskittyy pitkäikäisiin, kierrätettäviin laitteisiin ja materiaaleihin, jotka vähentävät elektroniikkajätteen määrää ja tukevat kiertotaloutta.

## P6.6 Hukkalämmön potentiaali ja energiatase

Käytännössä lähes kaikki IT-laitteiden ja sähköjärjestelmien kuluttama energia muuttuu lopulta **lämmöksi**. Hukkalämmön hyödyntäminen on siksi yksi tehokkaimmista tavoista parantaa datakeskuksen energiataseita ja pienentää sen hiilijalanjälkeä.

Hukkalämmön hyödyntämisen mahdollisuus ja kannattavuus arvioidaan jo esisuunnitteluvaiheessa. Mikäli hukkalämpö voidaan kytkeä esimerkiksi kaukolämpöverkkoon, datakeskuksen rakennussuunnittelussa huomioidaan:

- tarvittavat **lämmönvaihtimet**  
- **lämpöpumput** lämpötilan nostamiseksi lämmitykseen sopivaksi  
- liitynnät kaukolämpöverkkoon tai muihin lämpöä tarvitsemiin kohteisiin.

Hyvin suunniteltu järjestelmä voi siirtää merkittävän osan datakeskuksen käyttämästä sähköenergiasta hyötylämmöksi rakennusten tai prosessien lämmitykseen. Tämä:

- pienentää fossiilisilla polttoaineilla tuotetun lämmön tarvetta  
- vähentää kokonais-CO₂-päästöjä  
- parantaa datakeskuksen energiataseita (esim. ERF/REF-luvut).

Jos hukkalämmön hyödyntäminen ei ole mahdollista, lämpö poistetaan ympäristöön (esim. veteen tai ilmaan) voimassa olevien ympäristönormien mukaisesti – mutta vihreän datakeskuksen tavoitteena on, että **mahdollisimman suuri osa lämmöstä saadaan hyötykäyttöön**.

## P6.7 Esimerkkilaskelmia energiankulutuksesta ja päästöistä

Seuraavat yksinkertaistetut esimerkit havainnollistavat, miten energiankulutus, PUE ja päästöt liittyvät toisiinsa. Numerot ovat suuntaa-antavia ja ne voidaan korvata omilla laskelmillasi.

### Esimerkki 1: Päivittäinen energiankulutus

- IT-kuorma (palvelimet, tallennus, verkko): 500 kW  
- PUE = 1,4 (eli kokonaisteho 500 kW × 1,4 = 700 kW)

Päivittäinen energiankulutus:

- IT-energia: 500 kW × 24 h = 12 000 kWh  
- Kokonaisenergia: 700 kW × 24 h = 16 800 kWh

### Esimerkki 2: CO₂-päästöt eri sähköntuotantotavoilla

Oletetaan päästöintensiteetti:

- fossiilipainotteinen sähkö: 400 gCO₂/kWh (0,4 kgCO₂/kWh)  
- vähäpäästöinen sähkö (ydin + uusiutuvat): 60 gCO₂/kWh (0,06 kgCO₂/kWh)

Päivittäiset päästöt kokonaisenergiasta 16 800 kWh:

- fossiilipainotteinen: 16 800 kWh × 0,4 kgCO₂/kWh = 6 720 kgCO₂  
- vähäpäästöinen: 16 800 kWh × 0,06 kgCO₂/kWh = 1 008 kgCO₂

Erotus on **5 712 kgCO₂ per vuorokausi**, mikä vuodessa vastaa yli 2 000 tonnin eroa.

### Esimerkki 3: Hukkalämmön hyödyntäminen

Oletetaan, että:

- 70 % kokonaisenergiasta voidaan periaatteessa kerätä hukkalämpönä  
- 50 % kerätystä lämmöstä saadaan siirrettyä kaukolämpöverkkoon hyötylämmöksi.

Tällöin päivittäinen hyötylämpö:

- 16 800 kWh × 0,7 × 0,5 = 5 880 kWh / vrk hyötylämpöä.

Jos tämä hyötylämpö korvaa fossiilisilla polttoaineilla tuotettua kaukolämpöä (esim. 200 gCO₂/kWh), päästövähennys on:

- 5 880 kWh × 0,2 kgCO₂/kWh = 1 176 kgCO₂ / vrk.

Näiden esimerkkien avulla voidaan havainnollistaa, miten:

- **energiatehokkuus (PUE)**  
- **sähköntuotannon päästöintensiteetti**  
- **hukkalämmön hyödyntäminen**

yhdessä määrittävät datakeskuksen kokonais-CO₂-päästöt ja vihreyden tason.
