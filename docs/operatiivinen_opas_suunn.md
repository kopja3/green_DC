
# VIHREÄ DATAKESKUS: Operatiivinen opas suunnittelusta jatkuvaan optimointiin

*Itseopiskelumateriaali Green ICT -ammattilaisille*

***

## JOHDANTO: Kahdesta maailmasta vihreään datakeskukseen

Datakeskuksen rakentaminen ja operointi vaativat kahdenlaista ajattelua. Suunnitteluvaiheessa toimimme **complicated-maailmassa**: sähkömitoitus, jäähdytyskapasiteetti ja turvallisuusratkaisut ovat monimutkaisia, mutta periaatteessa laskettavissa ja ennakoitavissa. Näissä nojaudumme standardeihin, insinöörilaskelmiin ja todistettuihin käytäntöihin – emme keksi pyörää uudelleen.

Kun datakeskus käynnistyy, siirrymme **complex-maailmaan**: IT-kuormat vaihtelevat arvaamattomasti, ulkolämpötila heiluu, markkinasähkön hinta ja päästöintensiteetti muuttuvat tunneittain, ja hukkalämmön tarve vaihtelee vuodenajan mukaan. Tätä ei voi optimoida kerran ja lopullisesti vaan ainoastaan jatkuvalla mittaamisella, kokeilulla ja oppimisella (Snowden \& Boone, 2007).

**Vihreä datakeskus syntyy näiden kahden maailman vuoropuhelusta:** Hyvä perussuunnittelu luo mahdollisuudet, mutta todellinen energiatehokkuus ja ympäristövaikutusten minimointi syntyvät vasta operatiivisessa arjessa, kun järjestelmää säädetään jatkuvasti todellisten olosuhteiden mukaan.

Tämä opas käy läpi datakeskuksen keskeiset tekniset järjestelmät ja näyttää, miten ne liittyvät vihreään toimintaan – ensin suunnittelussa (complicated) ja sitten käytössä (complex).

***

## 1. IT-KUORMA: Kaikki alkaa palvelimista

### 1.1 Complicated-vaihe: Kapasiteetin mitoitus

IT-laitteet – palvelimet, tallennusjärjestelmät ja verkkolaitteet – ovat datakeskuksen ydin. Ne syövät sähköä ja tuottavat lämpöä, joka pitää poistaa. Suunnitteluvaiheessa arvioidaan:

**IT-tehon mitoitus:**

- Asennettu teho (kW): Kuinka monta räkkiä × teho per räkki
- Esimerkki: 50 räkkiä × 10 kW = 500 kW IT-teho
- Tehotiheys vaikuttaa jäähdytysratkaisuun (Rasmussen, 2005)

**Palvelutasopäätökset (SLA/SLO):**

- Saatavuustavoite (esim. 99,9% vs. 99,99%)
- Määrittää redundanssin tarpeen: N, N+1 vai 2N
- Korkeampi saatavuus = enemmän varalla olevaa kapasiteettia = pienempi käyttöaste = korkeampi PUE

**Tekninen valinta:** Ilmajäähdytys (<15 kW/räkki) vai nestejäähdytys (>15 kW/räkki)?

- HPC/AI-kuormat → usein 20-50 kW/räkki → nestejäähdytys välttämätön
- Perinteinen palvelutuotanto → 5-10 kW/räkki → ilmajäähdytys riittää


### 1.2 Complex-vaihe: Käyttöasteen optimointi

Kun konesali on käynnissä, energiatehokkuus ei riipu vain laitteista vaan siitä, **miten niitä käytetään**.

**Reaaliaikainen kuorman hallinta:**
IT-laitteiden sähkönkulutus ei ole lineaarinen. Tyhjäkäynnillä palvelin kuluttaa 40-60% maksimitehosta, vaikka tekee nollaa työtä (Barroso \& Hölzle, 2007). Tästä seuraa:

- **Matala käyttöaste (20-30%):** Energiaa hukataan – palvelin päällä mutta tyhjänä
- **Korkea käyttöaste (70-85%):** Optimaalinen – lähes kaikki sähkö menee oikeaan työhön
- **Liian korkea (>90%):** Riski ylikuormituksesta ja vasteajan pidenemiä

**Jatkuva optimointi käytännössä:**

1. **Konsolidointi:** Ajetaan työkuormia vähemmillä palvelimilla korkealla käyttöasteella
2. **Kuorman siirto:** Batch-työt ajetaan yöllä, kun sähkö halvempaa ja vähäpäästöisempää
3. **Virtualisointi:** Usea sovellus samalla fyysisellä palvelimella
4. **Automaattinen skaalaus:** Palvelimia kytketään pois päältä hiljaisen ajan (esim. viikonloput)

**Mittaaminen:** Reaaliaikainen IT-tehon seuranta PDU-tasolla (Power Distribution Unit) räkeittäin. Tavoite: käyttöaste >70%, mutta alle 85% (puskuria yllättäville huipuille).

**Miksi tämä on vihreyttä:**
Käyttöasteen nosto 30% → 70% voi pudottaa kokonaissähkönkulutusta 20-30%, koska tarvitaan vähemmän palvelimia ja siten vähemmän jäähdytystä (Shehabi et al., 2016).

***

## 2. SÄHKÖINFRASTRUKTUURI: Energia ja varmuus

### 2.1 Complicated-vaihe: Sähkömitoitus ja varmistus

Datakeskuksen sähköinfrastruktuuri mitoitetaan IT-tehon perusteella, mutta mukaan tulee jäähdytyksen, valaistuksen ja UPS-häviöiden osuus:

**PUE-pohjainen mitoitus:**

```
Kokonaisteho = IT-teho × PUE-tavoite
Esimerkki: 2 MW IT-teho × 1,25 PUE = 2,5 MW kokonaistarve
→ Sähköliittymä: 3 MW (puskuria huipuille)
```

**Varmistusperiaate (Tier-tasot):**

- **Tier I (N):** Yksi sähköketju, ei redundanssia
- **Tier II (N+1):** Varareservi yhdelle komponentille
- **Tier III (2N):** Kaksi täysin erillistä sähköketjua

**UPS (Uninterruptible Power Supply):**

- Tasoittaa verkkoheilahtelut
- Ylläpitää sähköä dieselgeneraattorin käynnistykseen (5-30 s)
- Häviöt: 5-10% läpi kulkevasta energiasta → vaikuttaa PUE:hen (Rasmussen, 2011)

**Varavoima (diesel/HVO/kaasu):**

- Mitoitus: IT-teho × PUE × 1,2 (varmuuskerroin)
- Polttoainesäiliö: 24-72 h autonomia
- Ympäristölupa jos >50 MW tai >100 m³ polttoainetta


### 2.2 Complex-vaihe: Dynaaminen energianhallinta

Käytössä sähkö ei ole staattinen asia – se on jatkuvasti muuttuva resurssi, jonka hinta, päästöt ja saatavuus vaihtelevat.

**Sähköverkon päästöintensiteetin seuranta:**
Suomen sähköverkossa päästökerroin vaihtelee 20-150 g CO₂/kWh tunnin välein riippuen siitä, paljonko tuulivoimaa, vesivoimaa ja tuontia käytetään (Fingrid, 2026). Vihreässä datakeskuksessa:

1. **Jatkuva seuranta:** Fingridin avoin API tarjoaa reaaliaikaisen päästökertoimen
2. **Kuorman ohjaus:** Batch-työt ajetaan silloin, kun päästöt ovat matalimmat (esim. tuulinen yö)
3. **Akkuvarasto (tulevaisuus):** Varastoidaan energiaa matalapäästöisinä hetkinä

**UPS-häviöiden minimointi:**
Modernit modulaariset UPS-järjestelmät skaalautuvat kuorman mukaan. Matalan kuorman aikana osa moduuleista voidaan kytkeä pois → häviöt pienemmät (Rasmussen, 2011).

**Varavoiman päästöt:**
Jos dieselgeneraattoria käytetään (verkkokatkoissa), päästöt kirjataan Scope 1 -päästöiksi. Suomessa verkko on luotettava (SAIDI <60 min/v), joten käyttö tyypillisesti <20 h/vuosi → vähäinen vaikutus (Energiavirasto, 2025).

**Mittaaminen:**

- Sähköliittymän mittari: Kokonaisteho reaaliajassa (kW), energia (kWh/päivä/kk)
- PDU-mittarit: IT-teho räkeittäin
- PUE laskenta: Liittymäenergia / IT-energia (tunti/päivä/kuukausi)

***

## 3. JÄÄHDYTYS: Suomen ilmaston hyödyntäminen

### 3.1 Complicated-vaihe: Jäähdytysjärjestelmän valinta

Jäähdytys on suurin yksittäinen energiasyöppö IT-laitteiden lisäksi. Oikea ratkaisu riippuu **tehotiheydestä** ja **ilmasto-olosuhteista**.

**Ilmajäähdytys + vapaajäähdytys (economizer):**

- **Soveltuvuus:** Tehotiheys <15 kW/räkki, Suomen ilmasto (viileä)
- **Periaate:** Ulkoilmaa käytetään suoraan tai välillisesti jäähdyttämään konesalin ilmaa
- **Free cooling -tunnit Suomessa:** 5 500-7 800 h/v (riippuu sijainnista)
- **Tyypillinen PUE:** 1,15-1,25

**Nestejäähdytys (direct-to-chip):**

- **Soveltuvuus:** Tehotiheys >15 kW/räkki, HPC/AI
- **Periaate:** Nestekierto (vesi/glykoliseos) siirtää lämmön suoraan prosessoreiden kylmälevyihin
- **Etu:** Lämpötila 35-45°C → soveltuu hukkalämmön hyödyntämiseen lämpöpumpulla
- **Tyypillinen PUE:** 1,10-1,20

**CRAH/CRAC-yksiköt:**

- **CRAH (Computer Room Air Handler):** Käyttää kylmävettä ilman jäähdytykseen
- **CRAC (Computer Room Air Conditioner):** Suora kylmäainekierto (kompressori)
- **Ohjaus:** Lämpötila/kosteuden säätö, VFD-puhaltimet (muuttuva kierrosluku)


### 3.2 Complex-vaihe: Dynaaminen jäähdytyksen optimointi

Jäähdytyksen tehokkuus ei ratkea mitoituksessa, vaan siinä, **miten järjestelmää ohjataan reaaliajassa**.

**Free cooling -potentiaalin maksimointi:**
Suomessa ulkolämpötila <15°C noin 60-85% vuoden tunneista. Tänä aikana mekaaninen jäähdytys (chiller) voidaan sammuttaa tai minimoida. Käytännössä:

1. **T_ulko <10°C:** 100% vapaajäähdytys, chiller pois päältä
2. **10°C < T_ulko < 18°C:** Hybridi, economizer + pieni chiller-tuki
3. **T_ulko >18°C:** Täysi mekaaninen jäähdytys

**Automaattinen ohjaus:**

- **Lämpötila-anturit:** 10-20 kohtaa konesalissa (hot spots!)
- **SCADA/BMS:** Building Management System ohjaa automaattisesti
- **Algoritmi:** Minimoi jäähdytysteho, mutta pidä T_sisä <27°C (ASHRAE A2-luokka)

**Hot aisle / Cold aisle -konfiguraatio:**
Räkit asetetaan niin, että kylmä ilma syötetään eteen (cold aisle) ja lämmin palautetaan takaa (hot aisle). Hot aisle containment (suljettu käytävä) estää kylmän ja lämpimän ilman sekoittumisen → jäähdytys 20-30% tehokkaampaa (Cho \& Kim, 2011).

**Kosteudenhallinnan optimointi:**
ASHRAE sallii 20-80% RH, mutta kapea ohjaus 40-60% kuluttaa energiaa turhaan. Uudempi käytäntö: annetaan kosteuden vaihdella 30-70% (ei aktiivista kostutuslaitetta) → säästö 5-10% jäähdytysenergiassa.

**Mittaaminen:**

- Jäähdytyksen sähköteho: HVAC-mittarit (kW)
- Lämpötilat: Sisä/ulko, supply/return air
- PUE-laskenta: Jos jäähdytys 400 kW ja IT-teho 2 000 kW → jäähdytyksen osuus = 400/2000 = 0,20 → PUE 1,20

**Miksi tämä on vihreyttä:**
Jokainen prosenttiyksikkö free coolingia on suora säästö jäähdytysenergiassa. Helsingissä 5 500 h free coolingia vs. Oulussa 7 000 h → Oulu säästää ~15% jäähdytysenergiassa → 0,03-0,05 yksikköä parempi PUE.

***

## 4. HUKKALÄMMÖN HYÖDYNTÄMINEN: ERF-optimointi

### 4.1 Complicated-vaihe: Hukkalämpöliittymän suunnittelu

Datakeskus tuottaa valtavan määrän lämpöä: 2 MW IT-teho → ~2 MW lämpöä 24/7/365. EU:n direktiivi edellyttää tämän hyödyntämistä, jos se on "teknisesti ja taloudellisesti toteutettavissa" (European Commission, 2023).

**Tekniset vaatimukset:**

- **Kaukolämpöverkko <5 km päässä** (pidempi matka → kallis putkisto)
- **Lämpötilat:** Datakeskuksen poisto 30-40°C, kaukolämpö vaatii 70-90°C → **lämpöpumppu**
- **Liittymäkapasiteetti:** Energiayhtiön verkko ottaa vastaan (MW)

**Lämpöpumpun mitoitus:**

- **COP (Coefficient of Performance):** Lämpöpumppu tuottaa 3-4 kW lämpöä jokaista 1 kW sähköä kohden
- **Esimerkki:** 2 MW datakeskus → 2 MW lämpöä → lämpöpumppu kuluttaa 500-650 kW sähköä → 2,5-3,5 MW lämpöä kaukolämpöön (70-80°C)

**ERF-laskenta:**

```
ERF = Hyödynnetty lämpö / IT-energia
Esimerkki: 30 000 MWh lämpöä kaukolämpöön / 36 000 MWh IT-energia
= 0,83 (83%)
```


### 4.2 Complex-vaihe: Sesonkien ja kysynnän mukaan

Lämmöntarve vaihtelee vuodenajan mukaan:

- **Talvi (marras-maalis):** Kaukolämpötarve korkea → kaikki hukkalämpö hyödynnetään
- **Kesä (kesä-elo):** Lämmöntarve matala → osa lämmöstä hylättävä dry coolerilla

**Dynaaminen ohjaus:**

1. **Reaaliaikainen viestintä energiayhtiön kanssa:** Energiayhtiö ilmoittaa hetkellisen tarpeen
2. **Lämpöpumpun säätö:** Lämpöpumppua ajetaan vain sen verran kuin lämpöä tarvitaan
3. **Hylkäämisjärjestelmä (dry cooler):** Kesäaikaan osa lämmöstä hylätään ilmaan, jos kysyntää ei ole

**Taloudellinen optimointi:**
Lämpö myydään kaukolämpöyhtiölle (tyypillisesti 30-50 €/MWh). Lämpöpumppu kuluttaa sähköä (60 €/MWh). Kannattavuus:

- Lämpöpumpun COP >3,5 → taloudellisesti kannattava
- COP <3,0 → rajatapaus, riippuu hinnoista

**Mittaaminen:**

- **Lämpömittari:** Kaukolämpöverkkoon luovutettu energia (MWh/kk)
- **Lämpöpumpun sähkö:** Mittari lämpöpumpun sähkönkulutukselle
- **ERF-raportointi:** Kuukausittain ja vuosittain (EU-raportointi)

***

## 5. MITTAUS JA AUTOMAATIO: Datan voima

### 5.1 Complicated-vaihe: Mittausinfrastruktuurin suunnittelu

**Mitä mitataan ja miksi:**
Ilman mittauksia emme tiedä, mikä toimii ja mikä ei. Datakeskuksessa mittaukset jakautuvat kolmeen kerrokseen:

**1. Energia (sähkö):**

- **Liittymämittari:** Kokonaisenergia (kWh, kW)
- **PDU-mittarit:** IT-laitteiden teho räkeittäin (24-100 kpl PDU:ta)
- **HVAC-mittarit:** Jäähdytyksen sähköteho
- **Valaistus ja muu:** Valaistuksen ja muun infrastruktuurin teho

**2. Lämpötila ja kosteus:**

- **T_sisä:** 10-20 lämpötila-anturia konesalissa (katto, lattia, hot/cold aisle)
- **RH_sisä:** Kosteus-anturit samoissa pisteissä
- **T_ulko / RH_ulko:** Ulko-olosuhteet free cooling -ohjaukseen

**3. Hukkalämpö (jos relevantti):**

- **Lämpömittari:** Kaukolämpöverkkoon luovutettu energia
- **Virtausmittarit:** Nesteen virtaus (m³/h) ja lämpötilaero (ΔT)

**Tallennusväli ja tarkkuus:**

- **Tallennusväli:** 1-5 min (PUE-laskenta edellyttää saman ajan dataa)
- **Tarkkuus:** Energiamittarit ±0,5-1%, lämpötila-anturit ±0,3°C
- **Datavarasto:** Keskitetty SCADA/BMS, varmuuskopiointi, säilytys >3 vuotta (auditointi)


### 5.2 Complex-vaihe: Reaaliaikainen ohjaus ja oppiminen

Mittausdatan arvo ei ole historiassa, vaan **päätöksenteossa nyt**.

**Reaaliaikainen dashboard (SCADA/BMS):**

```
┌────────────────────────────────────────┐
│ DATAKESKUS DASHBOARD - 7.2.2026 16:20 │
├────────────────────────────────────────┤
│ IT-teho:        1 847 kW (92% load)    │
│ Kokonaisteho:   2 278 kW               │
│ PUE (liukuva):  1,23                   │
│ T_sisä (avg):   23,4°C ✓               │
│ T_ulko:         -5°C → FREE COOLING ON │
│ Jäähdytys:      312 kW (chillers OFF)  │
│ Hukkalämpö:     1 620 kW → Kaukolämpö  │
│ ERF (kk):       0,78 (78%)             │
└────────────────────────────────────────┘
```

**Automaattiset hälytykset:**

- PUE >1,30 → Hälytys (mikä muuttui? Chiller käynnistyi kesällä?)
- T_sisä >27°C jossakin pisteessä → Kuuma piste (hot spot) → lisää ilmavirtausta
- IT-kuorma <30% → Mahdollisuus konsolidoida palvelimia

**Koneoppiminen ja ennakointi (kehittynyt taso):**
Tekoälyä voidaan käyttää jäähdytyksen optimointiin:

1. **Ennustetaan IT-kuorma** (historia + viikonpäivä + kausiluonteisuus)
2. **Ennustetaan ulkolämpötila** (sääennuste)
3. **Optimoidaan jäähdytys etukäteen:** Pre-cooling, jos lämpöaalto tulossa

Google raportoi 30-40% jäähdytysenergian säästön DeepMind-tekoälyllä (Evans \& Gao, 2016).

**Jatkuva parantaminen (kaizen):**

- **Viikkopalaveri:** PUE-trendi, poikkeamat, korjaustoimet
- **Kuukausiraportti:** Vertailu tavoitteeseen, trendit, sesongit
- **Vuosikatsaus:** ERF-kehitys, investointitarpeet, seuraavan vuoden tavoitteet

***

## 6. KÄYTTÖVARMUUS JA RESILIENS: Vihreyttä ja varmuutta

### 6.1 Complicated-vaihe: Redundanssin suunnittelu

Vihreä datakeskus ei tarkoita heikkoa datakeskusta. Käyttövarmuus rakennetaan redundanssilla:

**N+1 -periaate (Tier II-III):**

- Jokaiselle kriittiselle komponentille (UPS, chiller, pumppu) on yksi varalle
- Jos yksi hajoaa, palvelu jatkuu keskeytyksettä
- Huolto on mahdollista ilman palvelukatkoa

**2N -periaate (Tier IV):**

- Kaksi täysin erillistä sähkö- ja jäähdytysketjua
- Toinen ketju voi olla kokonaan huollossa, palvelu jatkuu
- Korkein varmuus, mutta kallis ja haastavampi PUE:lle (osakuorma-ongelma)

**Varavoiman testaus:**

- Dieselgeneraattori testataan kuukausittain 30-60 min
- Täysi failover-testi (siirto verkkosähköstä dieselille) 1-2 kertaa vuodessa


### 6.2 Complex-vaihe: Resilienssi muuttuvissa olosuhteissa

**Käyttövarmuus vs. energiatehokkuus -tasapaino:**
Tämä on vihreän datakeskuksen keskeinen jännite. Korkeampi redundanssi parantaa varmuutta, mutta huonontaa PUE:ta, koska:

- 2N-järjestelmät ajetaan 50% kuormalla (kaksi kertaa mitoitettua infraa)
- Osakuormalla UPS:n ja chillerin hyötysuhteet huonommat

**Dynaaminen optimointi:**
Moderni lähestymistapa: redundanssia **käytetään joustavasti**:

1. **Normaalitilanne:** Ajetaan mahdollisimman vähällä infralla (korkea käyttöaste → hyvä PUE)
2. **Kuormahuippu tai huoltotilanne:** Kytketään redundantit järjestelmät päälle
3. **Kriisitilanne:** Kaikki resurssit käyttöön

**Katastrofivalmius:**

- **Tulvariski:** Sähkökeskukset ja kriittiset järjestelmät lattiatasoa korkeammalla
- **Myrsky/lumikuorma:** Ulkoiset laitteet (dry cooler, ilmanvaihto) mitoitettu lumikuormalle
- **Kyberhyökkäys:** Ilmanvaihdon ja BMS:n eristäminen IT-verkosta (OT/IT-erottelu)

***

## 7. RAPORTOINTI JA JATKUVA PARANTAMINEN: Suljettu kehä

### 7.1 Complicated-vaihe: Raportoinnin rakenteet

**EU:n raportointivelvoite (≥500 kW IT-teho):**

- Vuosiraportti Energiavirastolle 30.4. mennessä
- Sisältö: PUE, REF, ERF, WUE, jäähdytysjärjestelmän tyyppi
- Mittausrajojen dokumentointi pakollinen

**Sisäinen raportointi:**

- **Reaaliaikainen:** Dashboard operaattoreille
- **Viikko:** PUE-trendi, poikkeamat
- **Kuukausi:** Energiankulutus, kustannukset, tavoitteiden seuranta
- **Vuosi:** Kokonaisarvio, investointipäätökset, seuraavan vuoden tavoitteet


### 7.2 Complex-vaihe: Oppiva organisaatio

**PDCA-sykli (Plan-Do-Check-Act):**

1. **Plan:** Asetetaan tavoite (esim. "PUE <1,20 kesäkaudella")
2. **Do:** Toteutetaan muutos (esim. "Nostetaan konesalin lämpötilatavoite 23°C → 25°C")
3. **Check:** Mitataan vaikutus (esim. "PUE laski 1,25 → 1,22, ei hot spotteja")
4. **Act:** Vakioidaan muutos tai perutaan

**Kokeilukulttuuri:**
Datakeskus on jatkuvan kokeilun alusta. Esimerkkejä:

- "Entä jos laskemme kosteuden alarajan 30% → 25%?" → Testi 2 viikkoa → Säästö 3% jäähdytysenergiassa
- "Entä jos sammutamme yöllä 10% palvelimista (ei-kriittinen kapasiteetti)?" → Testi viikonloppu → Säästö 8% kokonaisenergiassa, ei vaikutusta SLA:han

**Tiedon jakaminen:**

- Osallistuminen The Green Grid -yhteisöön ja benchmarking-ohjelmiin
- Julkiset PUE/ERF-raportit → läpinäkyvyys → kilpailuetu

***

## LOPUKSI: Matka, ei määränpää

Vihreä datakeskus ei ole projekti, joka "valmistuu". Se on jatkuva matka, jossa **suunnittelu luo mahdollisuudet** ja **käyttö realisoi potentiaalin**.

**Complicated-maailma** antoi meille:

- Oikein mitoitetun sähköinfrastruktuurin
- Tehokkaasti suunnitellun jäähdytysjärjestelmän
- Hukkalämmön liityntäpisteen kaukolämpöön
- Kattavan mittausinfrastruktuurin

**Complex-maailma** vaatii meiltä:

- Jatkuvaa kuuntelua: mitä data kertoo tänään?
- Ketteryyttä: IT-kuorma muuttui, mitä teemme?
- Kokeilua: testaamme uuden asetuksen, opimme, iteroimme
- Nöyryyttä: emme tiedä kaikkea, mutta opimme lisää joka päivä

**Energiatehokkuus syntyy rajapinnassa:** Kun insinööri, operaattori ja algoritmi keskustelevat jatkuvasti, ja jokainen virhe nähdään oppimismahdollisuutena.

**Tämä on Green ICT:n ydin:** Ei täydellisiä suunnitelmia, vaan tarpeeksi hyvät järjestelmät ja loputtoman oppimisen kulttuuri.

***

## LÄHTEET

Barroso, L. A., \& Hölzle, U. (2007). The case for energy-proportional computing. *Computer*, 40(12), 33-37.

Cho, J., \& Kim, B. S. (2011). Evaluation of air management system's thermal performance for superior cooling efficiency in high-density data centers. *Energy and Buildings*, 43(9), 2145-2155.

Energiavirasto. (2025). *Sähköverkon toimitusvarmuustilastot 2024*. Haettu osoitteesta https://www.energiavirasto.fi/

European Commission. (2023). Directive (EU) 2023/1791 on energy efficiency (recast). *Official Journal of the European Union*.

Evans, R., \& Gao, J. (2016). DeepMind AI reduces Google data centre cooling bill by 40%. *DeepMind Blog*. Haettu osoitteesta https://deepmind.google/discover/blog/

Fingrid. (2026). *CO₂-päästökertoimet Suomen sähkölle 2025*. Haettu osoitteesta https://data.fingrid.fi/

Rasmussen, N. (2005). *Electrical efficiency modeling for data centers* (White Paper 113). Schneider Electric.

Rasmussen, N. (2011). *Electrical efficiency modeling for data centers* (White Paper 113, Rev 1). Schneider Electric.

Shehabi, A., Smith, S., Sartor, D., Brown, R., Herrlin, M., Koomey, J., ... \& Lintner, W. (2016). *United States data center energy usage report*. Lawrence Berkeley National Laboratory.

Snowden, D. J., \& Boone, M. E. (2007). A leader's framework for decision making. *Harvard Business Review*, 85(11), 68-76.

***

**Sivumäärä:** 10 sivua (ilman lähteitä)
**Kohderyhmä:** ICT-ammattilaiset, datakeskusoperaattorit, tekninen johto
**Käyttötarkoitus:** Itseopiskelumateriaali, perehdytys, viitekehys


