
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

***

## Datakeskus for dummies – peruskäsitteet a–ö

### Adiabaattinen (jäähdytys / kostutus)

Adiabaattinen jäähdytys tai kostutus perustuu veden haihtumiseen ilmaan. Kun vettä sumutetaan tai höyrystetään ilmaan, veden höyrystyminen sitoo lämpöä ilmasta ja ilman lämpötila laskee, samalla ilman kosteus nousee.

### Akkuvarasto

Akkuvarasto on järjestelmä, jossa sähköenergiaa varastoidaan akkuihin ja puretaan takaisin verkkoon tai kuormille tarpeen mukaan. Datakeskuksessa akkuvarasto voi tukea UPS-järjestelmää tai osallistua dynaamiseen energianhallintaan (esimerkiksi hintapiikkien tasaamiseen).

***

### ASHRAE A2 -luokka

ASHRAE A2 -luokka on ilmastointiluokitus, joka määrittelee sallittuja lämpötila- ja kosteusalueita IT-laitteille. A2-luokassa sallittu lämpötila-alue on tyypillisesti 10–35 °C ja suhteellinen kosteus 20–80%.

***

### Automaattinen skaalaus

Automaattinen skaalaus (autoscaling) on järjestelmän kyky lisätä tai vähentää palvelinresursseja automaattisesti kuorman perusteella. Tavoitteena on pitää riittävä kapasiteetti palvelutasotavoitteen täyttämiseksi ilman pysyvää ylisuunnittelua.

***

### Automaattiset hälytykset, hälytysrajat

Automaattiset hälytykset ovat järjestelmän tuottamia ilmoituksia, jotka aktivoituvat, kun mitattu arvo ylittää ennalta määritellyn hälytysrajan. Datakeskuksessa hälytysrajoja määritellään esimerkiksi lämpötilalle, teholle ja PUE-arvolle.

***

### Automaatio

Automaatio tarkoittaa järjestelmiä, jotka ohjaavat laitteita (esimerkiksi pumppuja, puhaltimia ja venttiilejä) ilman jatkuvaa manuaalista ohjausta. Datakeskuksessa automaatio lukee mittaustietoja ja säätää jäähdytystä ja muita tukijärjestelmiä asetettujen tavoitteiden mukaan.

***

### Autonomia (24–72 h)

Autonomia tarkoittaa aikaa, jonka datakeskus voi toimia ilman valtakunnan verkon sähköä. Esimerkiksi 24–72 tunnin autonomialla viitataan varavoima- ja polttoainekapasiteettiin, joka riittää kyseiseksi ajaksi.

***

### Batch-työt

Batch-työt ovat eräajoja, joissa suuri määrä tehtäviä suoritetaan ilman välitöntä käyttäjäinteraktiota. Esimerkkejä ovat raporttien generointi ja analyysilaskenta. Batch-työt voidaan usein ajoittaa aikaan, jolloin sähkö on halvempaa tai vähäpäästöisempää.

***

### Benchmarking

Benchmarking on vertailua, jossa datakeskuksen suorituskykyä tai energiatehokkuutta verrataan muihin datakeskuksiin tai standardoituihin arvoihin. Vertailu voi perustua esimerkiksi PUE-arvoihin tai kapasiteettimittareihin.

***

### Chiller

Chilleri on mekaaninen jäähdytyslaite, joka poistaa lämpöä nesteestä kompressorin avulla. Jäähdytetty neste voidaan käyttää datakeskuksen ilman tai laitteiden jäähdyttämiseen.

***

### Complicated / complex (viitekehys)

Complicated-ympäristö on järjestelmä, jossa syy–seuraussuhteet ovat monimutkaisia mutta analysoitavissa, ja suunnittelu perustuu standardeihin ja laskentaan. Complex-ympäristö on järjestelmä, jossa syy–seuraussuhteet ovat osin ennakoimattomia, ja ohjaus perustuu jatkuvaan mittaamiseen, kokeiluun ja oppimiseen.

***

### Containment

Containment tarkoittaa rakenteita, joilla kuuma ja kylmä ilma erotetaan konesalissa. Esimerkkejä ovat suljetut kylmäkäytävät ja suljetut kuumakäytävät, joissa käytävä rajataan ovilla ja kattorakenteilla.

***

### COP (Coefficient of Performance)

COP on lämpöpumppujen ja jäähdytyslaitteiden suorituskykymittari, joka ilmaisee tuotetun lämpö- tai jäähdytysenergian suhteen käytettyyn sähköenergiaan. Esimerkiksi COP = 3 tarkoittaa, että yhdellä kilowattitunnilla sähköä tuotetaan kolme kilowattituntia lämpöä.

***

### CRAH / CRAC

CRAH (Computer Room Air Handler) käyttää jäähdytykseen kylmävesikiertoa ja puhaltimia.
CRAC (Computer Room Air Conditioner) käyttää suoraa kylmäainekiertoa ja kompressoria. Molemmat jäähdyttävät konesalin ilmaa.

***

### CUE (Carbon Usage Effectiveness)

CUE on mittari, joka kuvaa datakeskuksen hiilidioksidipäästöjä suhteessa IT-energiankulutukseen. Se lasketaan jakamalla kokonaispäästöt (kg CO₂) IT-energialla (kWh).

***

### Datakeskus

Datakeskus on tila tai rakennus, jossa on palvelimia, tallennus- ja verkkolaitteita sekä niitä tukevat sähkö-, jäähdytys- ja tietoliikennejärjestelmät. Datakeskuksessa ajetaan sovelluksia ja säilytetään dataa keskitetysti.

***

### Dieselgeneraattori

Dieselgeneraattori on polttomoottoriin perustuva varavoimalaite, joka muuntaa dieselpolttoaineen energian sähköksi. Datakeskuksessa dieselgeneraattori käynnistetään, kun valtakunnan verkon syöttö katkeaa pidemmäksi aikaa.

***

### Direct-to-chip

Direct-to-chip on nestejäähdytysratkaisu, jossa neste kiertää suoraan prosessorin ja muiden kriittisten komponenttien kylmälevyissä. Lämpö siirtyy suoraan komponentista nesteeseen ilman välissä olevaa ilmakerrosta.

***

### Dry cooler

Dry cooler on laite, jossa neste jäähdytetään ulkoilmaa käyttäen ilman veden haihduttamista. Neste kiertää lämmönvaihtimen läpi ja jäähtyy ulkolämpötilan mukaan, ilman avointa vesikiertoa.

***

### Dynaaminen energianhallinta

Dynaaminen energianhallinta tarkoittaa sähkönkulutuksen ja kuormien ohjaamista reaaliaikaisen tiedon perusteella. Ohjaus voi ottaa huomioon esimerkiksi sähkön hinnan, päästöintensiteetin ja kuormaprofiilin.

***

### Economizer

Economizer on jäähdytysratkaisu, joka hyödyntää ulkoilmaa tai ulkoilman viileyttä IT-laitteiden jäähdytyksessä. Direct economizer tuo ulkoilman suoraan konesaliin, kun taas indirect economizer käyttää lämmönvaihdinta.

***

### ERF (Energy Reuse Factor)

ERF on mittari, joka kuvaa, kuinka suuri osa datakeskuksen energiasta otetaan talteen ja hyödynnetään uudelleen, esimerkiksi kaukolämmössä. ERF lasketaan hyödynnetyn energian ja kokonaisenergian suhteena.

***

### EU:n raportointivelvoite, auditointi

EU:n raportointivelvoite edellyttää, että tietyt datakeskukset raportoivat vuosittain energiankulutuksesta ja kestävyysmittareista (kuten PUE, WUE, REF, ERF). Auditointi tarkoittaa viranomaisen tai kolmannen osapuolen tekemää tarkastusta, jossa raportoidut tiedot ja mittausjärjestelmä käydään läpi.

***

### Failover-testi

Failover-testi on suunniteltu koe, jossa datakeskus siirretään tahallisesti varajärjestelmän (esimerkiksi varavoiman) varaan. Tarkoitus on varmistaa, että siirtymä toimii suunnitellusti ilman palvelukatkosta.

***

### Fingridin avoin API

Fingridin avoin API on rajapinta, josta voi hakea Suomen sähköjärjestelmään liittyvää ajantasaista dataa, kuten sähkön päästökerrointa ja hintaa. Datakeskus voi käyttää tätä tietoa dynaamisessa energianhallinnassa.

***

### Hot aisle / cold aisle

Hot aisle / cold aisle on räkki- ja salijärjestely, jossa palvelinten etupuoli (kylmä puoli) on vastakkain kylmäkäytävässä ja takapuoli (kuuma puoli) vastakkain kuumakäytävässä. Järjestely erottaa kylmän ja kuuman ilman virtaukset.

***

### Hot spot

Hot spot on paikallinen alue konesalissa, jossa lämpötila nousee muita alueita korkeammaksi. Hot spot voi johtua heikosta ilmankierrosta, epätasaisesta kuormasta tai tukkeutuneista ilmanreiteistä.

***

### HPC / AI-kuormat

HPC (High Performance Computing) ja AI (Artificial Intelligence) -kuormat ovat laskentatehtäviä, jotka vaativat paljon prosessori- ja usein GPU-tehoa. Näiden tehotiheys räkissä on tyypillisesti korkea, mikä asettaa vaatimuksia jäähdytykselle.

***

### HVAC-mittarit

HVAC-mittarit mittaavat lämmitys-, ilmanvaihto- ja ilmastointijärjestelmien suureita, kuten ilmavirtaa, lämpötilaa ja sähkötehoa. Datakeskuksessa niitä käytetään jäähdytyksen toiminnan ja energiankulutuksen seurantaan.

***

### Hukkalämpö

Hukkalämpö on lämpöenergiaa, joka syntyy palvelimien ja muiden laitteiden sähkönkulutuksesta. Lähtökohtaisesti se poistetaan jäähdytysjärjestelmällä, mutta se voidaan myös ottaa talteen ja hyödyntää esimerkiksi rakennusten tai kaukolämmön lämmityksessä.

***

### Hukkalämpöliittymä

Hukkalämpöliittymä on tekninen liityntäpiste datakeskuksen ja lämpöä vastaanottavan järjestelmän (esimerkiksi kaukolämpöverkon) välillä. Se sisältää lämmönvaihtimen, putkiston ja mittauslaitteet.

***

### Hybridi jäähdytys

Hybridi jäähdytys yhdistää vapaajäähdytyksen (economizer) ja mekaanisen jäähdytyksen (chiller) samaan järjestelmään. Käyttötilaa vaihdetaan ulkolämpötilan ja kuorman perusteella.

***

### Hyötysuhde (osakuormalla)

Hyötysuhde osakuormalla kuvaa laitteen, kuten UPS:n tai chillerin, hyötysuhdetta, kun se toimii alle nimelliskuorman. Hyötysuhde on usein matalampi osakuormalla kuin lähellä nimelliskuormaa.

***

### Ilmajäähdytys / nestejäähdytys

Ilmajäähdytyksessä lämpö siirtyy palvelimista ilmaan, jota kierrätetään jäähdytyslaitteiden läpi. Nestejäähdytyksessä lämpö siirtyy suoraan tai epäsuorasti nesteeseen, jota jäähdytetään lämmönvaihtimissa tai dry coolereissa.

***

### IT-kuorma

IT-kuorma tarkoittaa datakeskuksessa ajettavien palveluiden ja sovellusten vaatimaa laskenta-, tallennus- ja verkkokapasiteettia. Se voidaan kuvata esimerkiksi palvelinmääränä, CPU- ja muistikuormana tai IT-tehona (kW).

***

### Jäähdytys

Jäähdytys on järjestelmä, joka poistaa IT-laitteiden tuottaman lämmön ja pitää lämpötilan sallituissa rajoissa. Jäähdytys voi perustua ilmaan, veteen tai muuhun jäähdytysnesteeseen.

***

### Jäähdytysarkkitehtuuri

Jäähdytysarkkitehtuuri kuvaa jäähdytysratkaisun kokonaisrakennetta: käytetyt laitteet (chiller, dry cooler, pumput), ilman ja nesteen reitit, lämpötilatasot ja ohjausperiaatteet.

***

### Kaizen

Kaizen on jatkuvan parantamisen periaate, jossa järjestelmää kehitetään pienin, toistuvin muutoksin. Datakeskuksessa kaizen voi tarkoittaa esimerkiksi säätöjen hienosäätöä ja toimintatapojen iteratiivista kehittämistä.

***

### Kapasiteetin mitoitus, sähkömitoitus

Kapasiteetin mitoitus tarkoittaa IT-laitteiden, jäähdytyksen ja sähköjärjestelmän mitoitusta ennustetun IT-kuorman mukaan. Sähkömitoitus on osa tätä ja sisältää liittymätehon, jakelun ja varavoiman mitoituksen.

***

### Katastrofivalmius

Katastrofivalmius on kyky ylläpitää toiminta tai palautua toimintaan merkittävän häiriön, kuten luonnonkatastrofin tai laajan sähkökatkon jälkeen. Se kattaa tekniset, organisatoriset ja prosessuaaliset varautumistoimet.

***

### Kaukolämpöverkko

Kaukolämpöverkko on putkisto ja siihen liittyvät laitokset, jotka siirtävät lämpöenergiaa lämmön tuotantolaitoksista rakennuksiin. Datakeskus voi syöttää hukkalämpöä verkkoon, jos lämpötila- ja kapasiteettivaatimukset täyttyvät.

***

### Koneoppiminen

Koneoppiminen on menetelmä, jossa algoritmit oppivat datasta ilman erillistä ohjelmointia kutakin tilannetta varten. Datakeskuksessa koneoppimista voidaan käyttää esimerkiksi jäähdytyksen optimointiin ja kuorman ennustamiseen.

***

### Konsolidointi

Konsolidointi tarkoittaa työkuormien keskittämistä harvemmille palvelimille, jolloin osa palvelimista voidaan sammuttaa. Tavoitteena on nostaa käyttöastetta ja vähentää energianhukkaa tyhjäkäynnillä.

***

### Kosteudenhallinta

Kosteudenhallinta tarkoittaa konesalin suhteellisen kosteuden säätelyä. Tavoitteena on välttää sekä liian alhainen kosteus (staattisen sähkön riski) että liian korkea kosteus (kondensaatioriski).

***

### Kostutuslaite

Kostutuslaite lisää kosteutta ilmaan, kun suhteellinen kosteus laskee alle asetetun rajan. Datakeskuksessa kostutus voidaan toteuttaa höyry- tai adiabaattisilla kostutuslaitteilla.

***

### Kuorman siirto

Kuorman siirto tarkoittaa IT-työkuormien ajankohdan tai sijainnin muuttamista. Esimerkki on batch-töiden siirtäminen yöaikaan tai toiseen datakeskukseen, jossa sähkö on halvempaa tai vähäpäästöisempää.

***

### Kytkin

Kytkin (switch) on verkkolaite, joka yhdistää palvelimet ja muut laitteet paikallisverkossa. Se välittää dataa laitteiden välillä MAC-osoitteiden perusteella.

***

### Käyttöaste

Käyttöaste kuvaa, kuinka suuri osa asennetusta kapasiteetista (esimerkiksi IT-tehosta) on käytössä. Se voidaan ilmoittaa prosentteina tai suhteena nimelliskapasiteettiin.

***

### Käyttövarmuus / resiliens

Käyttövarmuus kuvaa järjestelmän kykyä pysyä toiminnassa häiriöittä. Resiliens tarkoittaa kykyä sietää häiriöitä ja palautua niistä. Datakeskuksessa nämä liittyvät redundanssiin, varavoimaan ja palautumisprosesseihin.

***

### Kylmäainekierto

Kylmäainekierto on prosessi, jossa kylmäaine kiertää suljetussa järjestelmässä kompressorin, lauhduttimen, paisuntaventtiilin ja höyrystimen kautta. Kierto poistaa lämpöä jäähdytettävästä kohteesta.

***

### Kylmälevy

Kylmälevy (cold plate) on metallinen levy, joka kiinnitetään suoraan lämpöä tuottavan komponentin, kuten prosessorin, päälle. Levyssä kiertää neste, joka siirtää lämmön pois komponentista.

***

### Liittymäkapasiteetti

Liittymäkapasiteetti on kantaverkon tai jakeluverkon toimittajan kanssa sovittu suurin sähköteho, jonka datakeskus voi ottaa verkosta. Se mitataan yleensä megawatteina (MW).

***

### Liukuva PUE

Liukuva PUE on PUE-mittari, joka lasketaan liukuvan aikaikkunan (esimerkiksi viimeisen tunnin tai vuorokauden) perusteella. Sen avulla voidaan seurata muutoksia energiatehokkuudessa lyhyellä aikavälillä.

***

### Mittaus

Mittaus tarkoittaa tehojen, energioiden, lämpötilojen, kosteuden ja muiden muuttujien seuranta datakeskuksessa. Mittaustietoa käytetään hallintaan, raportointiin ja optimointiin.

***

### Moduulaarinen UPS

Moduulaarinen UPS koostuu useista rinnakkaisista moduuleista, joita voidaan lisätä tai poistaa kuorman mukaan. Tällä pyritään pitämään yksittäisten moduulien käyttöaste korkeampana ja häviöt pienempinä.

***

### N, N+1, 2N

N tarkoittaa mitoitettua peruskapasiteettia, joka riittää kuorman kattamiseen.
N+1 tarkoittaa, että peruskapasiteetin lisäksi on yksi varakomponentti.
2N tarkoittaa kahta täysin erillistä, kuorman kantamiseen riittävää järjestelmää.

***

### OT/IT-erottelu

OT (Operational Technology) tarkoittaa fyysisten laitteiden ohjausjärjestelmiä, kuten BMS ja SCADA. IT (Information Technology) tarkoittaa tietojärjestelmiä ja sovelluksia. OT/IT-erottelu tarkoittaa näiden verkkojen ja järjestelmien eriyttämistä tietoturvan ja toimintavarmuuden vuoksi.

***

### Palvelin

Palvelin on verkkoon liitetty tietokone, joka tarjoaa palveluja muille laitteille. Datakeskuksessa palvelimet on optimoitu jatkuvaan käyttöön ja etähallittavuuteen.

***

### Palvelutasopäätökset

Palvelutasopäätökset määrittävät, millaista laatua ja saatavuutta palveluilta vaaditaan. Ne kirjataan usein SLA- ja SLO-tavoitteiksi, jotka ohjaavat kapasiteetin ja redundanssin suunnittelua.

***

### PDCA (Plan–Do–Check–Act)

PDCA on jatkuvan parantamisen malli.
Plan: suunnitellaan muutos,
Do: toteutetaan se,
Check: arvioidaan tulokset,
Act: vakiinnutetaan tai korjataan toiminta tulosten perusteella.

***

### PDU (Power Distribution Unit)

PDU on räkkitasoinen sähkönjakeluyksikkö, joka jakaa virran UPS:ltä tai jakelukeskukselta palvelimille. Älykkäissä PDU-yksiköissä on myös mittaus- ja kytkentäominaisuuksia.

***

### Pre-cooling

Pre-cooling tarkoittaa ennakoivaa jäähdytystä, jossa tilaa jäähdytetään etukäteen ennen odotettua kuormanhuhka tai lämpötilan nousua. Se voi hyödyntää esimerkiksi viileitä yöolosuhteita.

***

### PUE (Power Usage Effectiveness)

PUE on suhdeluku, joka kuvaa datakeskuksen kokonaisenergiankulutuksen ja IT-laitteiden energiankulutuksen suhdetta. PUE = E_total / E_IT.

***

### Päästöintensiteetti / päästökerroin

Päästöintensiteetti tai päästökerroin kuvaa, kuinka paljon hiilidioksidipäästöjä syntyy tuotettua energiayksikköä kohden, esimerkiksi g CO₂/kWh. Sitä käytetään sähkönkulutuksen muuntamiseen päästöiksi.

***

### Räkki

Räkki on standardoitu kehikko, johon palvelimet ja muut laitteet asennetaan. Tyyppiräkin korkeus on esimerkiksi 42U, ja leveys 19 tuumaa.

***

### Reaaliaikainen dashboard

Reaaliaikainen dashboard on näkymä, jossa keskeiset mittarit, kuten IT-teho, kokonaisteho, PUE, lämpötilat ja hälytykset, esitetään ajantasaisesti. Se tukee operatiivista päätöksentekoa.

***

### Redundanssi

Redundanssi tarkoittaa päällekkäistä kapasiteettia tai laitteita, jotka ottavat toiminnon hoitaakseen vian tai huollon aikana. Redundanssi lisää käyttövarmuutta.

***

### REF (Renewable Energy Factor)

REF kuvaa, kuinka suuri osuus datakeskuksen käyttämästä energiasta on peräisin uusiutuvista lähteistä. Se lasketaan uusiutuvan energian ja kokonaisenergian suhteena.

***

### RH (relative humidity)

RH on suhteellisen kosteuden mitta, joka ilmaisee ilman vesihöyrymäärän prosenttiosuutena ilman maksimikapasiteetista tietyssä lämpötilassa.

***

### Reititin

Reititin (router) ohjaa tietoliikennettä eri verkkojen välillä. Se päättää, mihin reittiin data ohjataan perustuen IP-osoitteisiin ja reititysprotokolliin.

***

### Sähköinfrastruktuuri

Sähköinfrastruktuuri kattaa muuntajat, pää- ja alakeskukset, kaapeloinnin, UPS-laitteet, PDU-yksiköt ja suojalaitteet, jotka tuovat ja jakavat sähkön datakeskuksessa.

***

### Sähkönjakelu datakeskuksessa

Sähkönjakelu datakeskuksessa on ketju muuntajalta pääkeskukseen, edelleen alakeskuksiin, UPS-laitteille ja PDU-yksiköille, ja lopulta IT-laitteille. Jakeluun kuuluu suojalaitteita ja mittareita.

***

### Sähkösyöttö

Sähkösyöttö on kokonaisuus, joka kuvaa, mistä ja miten sähkö tuodaan datakeskukseen. Siihen kuuluu liittymä valtakunnan verkkoon, muuntajat ja jakelujärjestelmä.

***

### SCADA / BMS (Building Management System)

SCADA (Supervisory Control And Data Acquisition) ja BMS ovat järjestelmiä, jotka keräävät mittaustietoja ja ohjaavat laitteita, kuten jäähdytysjärjestelmiä ja ilmanvaihtoa. Ne tarjoavat valvonta- ja ohjausrajapinnan operaatiohenkilöstölle.

***

### SLA / SLO

SLA (Service Level Agreement) on sopimus palvelutasosta asiakkaan ja palveluntarjoajan välillä.
SLO (Service Level Objective) on mitattava tavoitteellinen arvo palvelutasolle, kuten saatavuusprosentti tai vasteaikaraja.

***

### Supply air / return air

Supply air on jäähdytetty ilma, joka johdetaan palvelimille. Return air on lämmin ilma, joka palaa palvelimilta jäähdytysjärjestelmään.

***

### Tallennusjärjestelmä

Tallennusjärjestelmä varastoi dataa levyjen tai flash-muistien varaan. Järjestelmä voi olla jaettu monelle palvelimelle (SAN, NAS) tai liitetty suoraan yksittäisiin palvelimiin.

***

### The Green Grid

The Green Grid on kansainvälinen organisaatio, joka kehittää datakeskusten energiatehokkuuden mittareita ja ohjeistuksia, kuten PUE-, WUE-, CUE-, REF- ja ERF-mittareita.

***

### Tier-tasot (Tier I/II/III/IV)

Tier-tasot ovat Uptime Instituten määrittelemiä datakeskusten luokitusasteita, jotka kuvaavat käyttövarmuutta ja redundanssia.
Tier I: yksinkertainen infrastruktuuri, ei redundanssia
Tier II: osittainen redundanssi
Tier III: huoltovarma, N+1-ratkaisut
Tier IV: kahdennettu 2N-infrastruktuuri

***

### Tietoliikenneyhteydet

Tietoliikenneyhteydet yhdistävät datakeskuksen muihin verkkoihin valokuidun ja muiden siirtomedioiden kautta. Yhteyksissä huomioidaan kaistanleveys, viive ja redundanssi.

***

### Turvallisuus

Turvallisuus kattaa fyysisen turvallisuuden (kulunvalvonta, kamerat, lukitukset) ja tietoturvan (verkko- ja järjestelmäsuojaus). Tavoitteena on estää luvaton pääsy ja häiriöt.

***

### UPS (Uninterruptible Power Supply)

UPS on laite, joka tarjoaa katkottoman sähkösyötön lyhyiden katkosten ja jänniteheilahteluiden aikana. Se perustuu tyypillisesti tasasuuntaajaan, invertteriin ja akustoon.

***

### UPS-häviöt

UPS-häviöt ovat energiahäviöitä, jotka syntyvät sähköä muunnettaessa UPS:n läpi. Ne ilmenevät lämpönä ja kasvattavat datakeskuksen kokonaisenergiankulutusta.

***

### Val takunnan verkko

Valtakunnan verkko on kansallinen sähköjärjestelmä, jota kantaverkkoyhtiö operoi. Se siirtää sähkön tuotantolaitoksista kulutuskohteisiin, mukaan lukien datakeskukset.

***

### Varavoima

Varavoima on sähkönsyöttö, joka korvaa valtakunnan verkon syötön sen häiriintyessä. Datakeskuksessa varavoimana käytetään yleensä diesel- tai kaasugeneraattoreita ja UPS-järjestelmiä.

***

### Varmuuskerroin

Varmuuskerroin on suunnittelussa käytetty kerroin, jolla mitoitettua kapasiteettia kasvatetaan ennusteen epävarmuuden ja häiriöiden varalta. Esimerkiksi 1,2 tarkoittaa 20% ylisuunnittelua.

***

### Vapaajäähdytys / free cooling

Vapaajäähdytys hyödyntää ulkoilmaa tai ulkoilman viileyttä jäähdytyksessä ilman tai vähäisellä mekaanisella jäähdytyksellä. Se pienentää jäähdytyksen sähkönkulutusta erityisesti viileässä ilmastossa.

***

### Verkkoheilahtelut

Verkkoheilahtelut ovat jännitteen tai taajuuden vaihteluita sähköverkossa. Ne voivat aiheuttaa häiriöitä laitteissa, minkä vuoksi datakeskuksessa käytetään UPS-laitteita ja suojauksia.

***

### Virtualisointi

Virtualisointi on tekniikka, jossa yksi fyysinen palvelin jakaa resurssinsa useisiin virtuaalisiin palvelimiin. Se mahdollistaa resurssien joustavan käytön ja konsolidoinnin.

***

### Virtausmittarit

Virtausmittarit mittaavat nesteen tai ilman virtausnopeutta ja -määrää putkistoissa tai kanavissa. Datakeskuksessa niitä käytetään esimerkiksi jäähdytysnesteen ja ilmanvaihdon valvontaan.

***

### WUE (Water Usage Effectiveness)

WUE on mittari, joka kuvaa vedenkulutusta suhteessa IT-energiankulutukseen. Se lasketaan vedenkäytön (litraa) ja IT-energian (kWh) suhteena.

***

### Ympäristövaikutus

Ympäristövaikutus on kokonaisuus, joka kuvaa datakeskuksen vaikutusta ympäristöön. Siihen sisältyvät muun muassa sähkönkulutuksesta aiheutuvat päästöt, jäähdytyksen ja mahdollisen vedenkäytön vaikutukset sekä laitteiden elinkaarivaikutukset.

***

### ΔT (lämpötilaero)

ΔT on kahden lämpötilan erotus. Jäähdytyksessä ΔT kuvaa usein sisään- ja ulostulevan ilman tai nesteen lämpötilaeroa, jolla voidaan arvioida siirtyneen lämmön määrää.

