# Liite X — Hankintaliite: vaaditut dokumentit, minimitasot, todennukset ja asiakkaalle luovutettava mittausdata (API/raportit)

**Soveltamisala:** Tämä liite koskee vihreän datakeskuksen (oma DC tai colocation-palvelu) sähkö–IT–jäähdytys–hukkalämpö -ketjun **mitattavuutta, raportointia ja todennettavuutta**, jotta energiatehokkuus (PUE) ja muut vihreysvaatimukset eivät jää väitteiksi vaan voidaan osoittaa datalla. [2][4][6][7][9]

**Toteutusperiaate:** PUE ja johtaminen edellyttävät vähintään *kokonaisenergian* ja *IT-energian* erottelua; lisäksi UPS-häviöt ja jäähdytyksen energia tulee pystyä osoittamaan osajärjestelmätasolla. [2][6][7]

---

## 1) Vaaditut dokumentit (Deliverables) ja minimitasot

### 1.1 Suunnittelu- ja sopimuspaketti (ennen rakentamista / palvelusopimuksen allekirjoitusta)

1) **Sähköketjun arkkitehtuuri (SLD + varmistusratkaisut)**
- **Sisältö (minimi):** verkko-/liittymätaso, muuntajat, UPS, generaattorit/varavoima, jakelukeskukset, PDU/räkki-syöttö, mitoitusperiaate myös osakuormilla. [6][7]  
- **Todennus:** suunnittelukatselmus + ristiriidattomuus mittauspistekarttaan (kohta 1.2).  
- **Asiakkaalle näkyvä data:** ks. luku 2 (UPS in/out, PDU, total).

2) **Mittauspistekartta (Instrumentation & Metering Map)**
- **Sisältö (minimi):** mittauspiste-ID, sijainti, suure (kW/kWh, A/V, lämpötila, virtaama), tarkkuusluokka, näytteenotto, kalibrointi, datapolku (mittari → järjestelmä). [2][6][7]  
- **Minimitaso PUE:n kannalta:**  
  - *Kokonaisenergia* (facility total)  
  - *IT-energia* (PDU/räkki tai IT-syöttö)  
  - *UPS sisään ja ulos* (häviöiden laskenta) [2][6][7]  
- **Todennus:** mittausketjun “end-to-end” -testisuunnitelma (SAT/FAT), ks. luku 3. [2][4]

3) **Mittarimäärittelyt ja laskentasäännöt (KPI & Calculation Rules)**
- **Sisältö (minimi):** PUE-laskenta (rajaukset, aikajänne, mittauslähteet), jäähdytysenergian osuus, IT-kuorman mittausperiaate, mahdolliset päästö-/uusiutuvuuslaskennan periaatteet. [2][4][7][9]  
- **Todennus:** laskentasääntöjen auditointi + näyteraportti 30 päivän datalla (tai simuloidulla datalla hankintavaiheessa).

4) **DCIM/BMS- ja datamalli-kuvaus (Data Model & Ownership)**
- **Sisältö (minimi):** mitä järjestelmiä käytetään (DCIM/BMS), datan omistajuus, säilytysajat, aikaleimapolitiikka, muutosloki (audit trail). [2][4]  
- **Todennus:** tietomallin katselmus + API/raportoinnin läpikäynti (luku 2).

5) **Hukkalämmön hyödyntämisen esisuunnitelma**
- **Sisältö (minimi):** talteenottokohta (mistä lämpö), lämpötaso (°C), siirtoteho (kW), vastaanottaja (kaukolämpö/kiinteistö/teollisuus), mittaus (MWh siirretty). [7][9]  
- **Todennus:** esisopimus/LOI tai liityntäehdot + mittausperiaate.

---

### 1.2 Rakentamisen / toimituksen dokumentit (asennus + käyttöönotto)

6) **As-built-dokumentaatio**
- **Sisältö (minimi):** toteutuneet kytkennät, mittauspisteet, sensori- ja mittariluettelo, järjestelmärajapinnat, setpointit, muutosten historia. [6][7]  
- **Todennus:** as-built-vertailu suunnitelmaan + hyväksymispöytäkirja.

7) **Käyttöönotto- ja testauspaketti (Commissioning, FAT/SAT)**
- **Sisältö (minimi):** kuormitustestit, baseline-mittaukset, PUE-laskenta käytännössä, datan laatu (katkot/aikaleimat), hälytysrajat. [4][7]  
- **Todennus:** hyväksytty commissioning-raportti + KPI:t vähintään 2 kuormatasolla (esim. 25% ja 75% tai sovittu). [4]

8) **Jäähdytyksen säätö- ja todentamisdokumentit**
- **Sisältö (minimi):** asetuspisteet, ohjauslogiikka, mittarit (lämpötila, ΔT, virtaamat), ja jäähdytyksen energian erottelu. [4][6][7]  
- **Todennus:** toiminnallinen testi: kuormamuutos → jäähdytysjärjestelmä reagoi → vaikutus näkyy mittareissa. [4]

9) **Verkon energiamittauksen ja ohjauksen dokumentit**
- **Sisältö (minimi):** verkon kulutuksen näkyvyys (laite-/ryhmätaso), liikenneprofiili ja energiatilat/konfiguraatioperiaatteet. [8]  
- **Todennus:** näyteraportti (liikenne vs kulutus) ja dokumentoidut toimintamallit vajaakuormaan/ruuhkaan. [8]

---

### 1.3 Operoinnin ja raportoinnin dokumentit (palvelutuotanto)

10) **Operointimalli: “mittaa → analysoi → muutos → todenna → vakioi”**
- **Sisältö (minimi):** poikkeamien käsittely, muutoshallinta, energiatehokkuuskatselmukset, vastuut (RACI), trendiseuranta. [2][4]  
- **Todennus:** 1) kuukausiraportti 2) muutosesimerkki, jossa vaikutus todennetaan KPI:llä. [2][4]

11) **Uusiutuvan sähkön ja päästöjen raportointipaketti**
- **Sisältö (minimi):** sähkön alkuperän todennus, päästöintensiteetin periaate ja raportointimuoto (esim. kuukausittain). [9]  
- **Todennus:** dokumentoitu todennusketju (todisteet + laskentaperiaate). [9]

12) **Hukkalämmön raportointi**
- **Sisältö (minimi):** siirretty lämpöenergia (MWh), lämpötasot, käyttöaste ja (tarvittaessa) arvio korvausvaikutuksesta raportoituina oletuksina. [9]  
- **Todennus:** mittaridataan perustuva raportti (ei pelkkä arvio). [9]

---

## 2) Asiakkaalle luovutettava mittausdata (API/raportit)

### 2.1 Pakolliset datapisteet (aikasarjat)

**Sähkö**
- Kokonaiskulutus (facility total): kW + kWh (min. 15 min aggregointi). [2][6][7]  
- IT-energia (IT load): kW + kWh (PDU/räkki tai IT-syöttö). [2][6][7]  
- UPS: input kW/kWh, output kW/kWh (häviöt = input–output). [6][7]  
- (Suositus) Jakelutasot: ryhmäkeskus / PDU / räkki (riittävä granulariteetti kapasiteetin ja optimoinnin ohjaukseen). [2][7]

**Jäähdytys**
- Jäähdytyksen sähkönkulutus (chillerit/pumput/puhaltimet eriteltynä vähintään yhtenä kokonaisuutena; mieluiten laite- tai alajärjestelmätasolla). [4][7]  
- Lämpötilat (vähintään rack inlet / huone + tulo/paluu jos neste), ΔT, ja virtaamat (jos vesikierto). [4][7]

**Verkko**
- Verkkolaitteiden kulutus (kokonaisuutena ja/tai laite-/ryhmätaso) + liikenneprofiilin mittari (esim. throughput). [8]

**Hukkalämpö**
- Siirretty lämpöenergia (MWh), siirtoteho (kW), meno/paluu-lämpötilat ja virtaama (jos käytössä). [7][9]

**Uusiutuva ja päästöt**
- Uusiutuvan osuuden todennus (raportoituna) + käytetty päästöintensiteetti ja laskentaperiaate raportissa. [9]

---

### 2.2 Rajapinnat ja toimitusmuodot (minimivaatimus)

**API / dataexport (pakollinen)**
- **Formaatti:** vähintään CSV ja JSON (aikasarjat + metatiedot).  
- **Sisältö:** datapisteen ID, kuvaus, yksikkö, aikaleima (timezone), laatu-/statuskenttä (OK/puuttuu/arvio), lähdejärjestelmä. [2][4]  
- **Saatavuus:** vähintään 99% mittausdatan saatavuus kuukausitasolla (poislukien sovitut huoltoikkunat).  
- **Viive:** data saatavilla viimeistään T+24h (suositus: lähes reaaliaikainen).  
- **Säilytys:** vähintään 24 kk aikasarjat; aggregaatit (päivä/kk) vähintään 5 vuotta.

**Raportit (pakollinen)**
- **Kuukausiraportti (PDF/HTML):** PUE, IT-energia, jäähdytysenergia, UPS-häviöt, poikkeamat ja tehdyt muutokset (audit trail -yhteys). [2][4][7]  
- **Hukkalämpöraportti:** MWh siirretty + käyttöaste + keskeiset lämpötasot. [9]  
- **Uusiutuva/päästöt:** todennus ja laskentaperiaate liitteenä. [9]

---

## 3) Todennus ja hyväksymiskriteerit (Acceptance)

### 3.1 Mittausketjun hyväksyntä (pakollinen “end-to-end”)
**Hyväksyntätesti:** “mittari → data → laskenta → raportti” toimii ilman käsityötä. [2][4]  
- Aikaleimat oikein (ei “samoja leimoja” / ei drift-ongelmaa).  
- Puuttuvat datapisteet merkitään puuttuviksi (ei hiljaista interpolointia ilman merkintää).  
- PUE voidaan laskea sovituilla säännöillä vähintään 30 päivän aineistolla (tai commissioning-jaksolla). [2][4]

### 3.2 UPS-häviöiden todennus
- UPS input/output mitattu ja raportoitu → häviö näkyy sekä hetkellisessä että kumulatiivisessa energiassa. [6][7]

### 3.3 Jäähdytyksen ohjattavuuden todennus
- Kuormamuutos → jäähdytysjärjestelmän ohjaus reagoi → vaikutus näkyy jäähdytysenergiassa ja lämpötiloissa/ΔT:ssä. [4][7]

### 3.4 Hukkalämmön mittauksen todennus
- Siirretty lämpöenergia (MWh) perustuu mitattuun virtaamaan ja lämpötiloihin tai suoraan lämpöenergiamittariin; raportointi perustuu dataan. [7][9]

---

## 4) Jos toimitusmalli on colocation (et rakenna itse)

**Lisää sopimukseen vähintään:**
- asiakkaalle toimitettava IT-energiamittaus (kWh) + facility total tai PUE-raportointi sovitulla menetelmällä, sekä UPS-häviöiden näkyvyys (vähintään keskitettynä). [2][6][7]  
- dataexport/API tai säännöllinen raportointi, joka mahdollistaa oman analytiikan (ei pelkkä “dashboard-kuva”). [2][4]  
- uusiutuvan sähkön todennus ja päästöraportointi periaatteineen. [9]

---

# Lähteet (APA, numerointi)

[1] Jin, X., Zhang, Y., Vasilakos, A. V., & Liu, Z. (2016). *Green data centers: A survey, perspectives, and future directions* (arXiv:1608.00687).

[2] Uddin, M., & Rahman, A. A. (2012). Energy efficiency and low carbon enabler green IT framework for data centers considering green metrics. *Renewable and Sustainable Energy Reviews, 16*(6), 4078–4094.

[3] Pierson, J.-M., Baudic, G., Caux, S., Celik, B., Costa, G., Grange, L., … Varnier, C. (2019). DATAZERO: Datacenter with zero emission and robust management using renewable energy. *IEEE Access*.

[4] Sharma, P., Pegus II, P., Irwin, D. E., Shenoy, P., Goodhue, J., & Culbert, J. (2017). Design and operational analysis of a green data center. *IEEE Internet Computing, 21*(4), 16–24.

[5] *Energy storage techniques, applications, and recent trends – A sustainable solution for power storage*. (n.d.). **Tarkennettava tekijä- ja julkaisudata ennen julkaisemista.**

[6] Barroso, L. A., Clidaras, J., & Hölzle, U. (2013). *The datacenter as a computer: An introduction to the design of warehouse-scale machines* (2nd ed.). Morgan & Claypool.

[7] Geng, H. (Ed.). (2014). *Data center handbook*. John Wiley & Sons.

[8] Bilal, K., Malik, S. U. R., Khalid, O., Hameed, A., Alvarez, E., Wijaysekara, V., … Khan, S. U. (2014). A taxonomy and survey on green data center networks. *Future Generation Computer Systems, 36*, 189–208.

[9] Liikenne- ja viestintäministeriö. (2020). *The ICT sector, climate and the environment – Interim report* (Publications of the Ministry of Transport and Communications 2020:14).
