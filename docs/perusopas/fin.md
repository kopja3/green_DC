# 5. Datakeskuksen toiminta vaiheittain – Syventävä osuus

> **Edellytys**: Tämä luku olettaa, että olet lukenut itseopiskelumateriaalin Moduuli 4:n ja ymmärrät datakeskuksen energiaketjun perusperiaatteet (sähkö → IT-kuorma → lämpö → talteenotto).

---

## P5.0 Mitä tässä luvussa tapahtuu

Itseopiskelumateriaalissa kuvattiin datakeskuksen energiaketju ylätasolla. Tässä luvussa syvennytään siihen, **miten** nämä vaiheet toteutetaan käytännössä ja **miksi** tietyt valinnat tehdään.

Sen sijaan että toistaisimme perusasiat, keskitymme:
- **Päätöksentekoon**: Milloin valitaan ratkaisu A eikä B?
- **Käytännön esimerkkeihin**: Mitä oikeissa datakeskuksissa tapahtuu?
- **Yhteyksiin**: Miten yksi vaihe vaikuttaa toiseen?
- **Optimointiin**: Miten saadaan vihreämpi kokonaisuus?

---

## P5.1 Energiaketjun dynamiikka: Mistä vihreys oikeasti syntyy?

Itseopiskelumateriaalissa kuvasimme energiaketjun lineaarisena: sähkö → palvelin → verkko → jäähdytys → lämpö. Todellisuudessa ketju on **dynaaminen järjestelmä**, jossa jokainen osa vaikuttaa kaikkiin muihin.

### Esimerkki: Palvelimen ja jäähdytyksen välinen vuorovaikutus

Perinteinen ajattelu:
```
1. Valitse palvelimet (ne tuottavat X kW lämpöä)
2. Mitoita jäähdytys (poista X kW lämpöä)
```

Vihreä ajattelu:
```
1. Valitse palvelimet JA jäähdytys yhdessä
   - Korkeampi tehotiheys → nestejäähdytys → parempi hyötysuhde
   - Matalampi tehotiheys → ilmajäähdytys vapaajäähdytyksellä
   
2. Säädä molempia dynaamisesti
   - Siirrä kuormia palvelimien välillä jäähdytyksen mukaan
   - Säädä jäähdytystä palvelinkuorman mukaan
```

### Case: Googlen AI-optimointi

Google raportoi 40 % jäähdytysenergian vähennyksen käyttämällä tekoälyä ohjaamaan:
- Jäähdytyksen lämpötiloja
- Puhaltimien nopeuksia  
- Vapaajäähdytyksen hyödyntämistä
- **Ja palvelinkuormien sijoittelua**

Viimeinen kohta on keskeinen: AI ei vain optimoinut jäähdytystä, vaan **siirsi työkuormia sinne, missä ne oli helpompi jäähdyttää**. Tämä on järjestelmätason optimointia.

---

## P5.2 Sähkönsyöttö: Tehokkuuden ja varmuuden tasapaino

### Päätöksenteko: Kuinka monta muuntajaa?

Itseopiskelumateriaalissa mainittiin N+1 -redundanssi. Käytännössä valinta on monimutkaisempi:

| Ratkaisu | Investointi | Energiatehokkuus | Varmuus | Milloin käyttää? |
|----------|-------------|------------------|---------|-------------------|
| **N (ei redundanssia)** | Halvin | Paras (yksi muuntaja täydellä kuormalla) | Heikko | Ei-kriittiset palvelut |
| **N+1** | Keskitaso | Hyvä (muuntajat 60-80% kuormalla) | Hyvä | Yleisin valinta |
| **2N (täysi kahdennus)** | Kallein | Heikko (muuntajat 30-40% kuormalla) | Paras | Kriittisimmät palvelut |

**Vihreä valinta**: N+1 oikealla mitoituksella. Muuntajat toimivat 60-80 % kuormalla, jossa niiden hyötysuhde on paras. 

### Käytännön esimerkki: UPS-valinta

Kysymys ei ole "Tarvitaanko UPS?" (vastaus: kyllä), vaan "Millainen UPS?"

**Skenaario 1: Pieni yritys (100 kW IT-kuorma)**
- Valinta: Line-interactive UPS
- Perustelu: Halvempi, hyötysuhde 95%, riittävä suojaus
- Kompromissi: 2-5 ms vaihtaika varavirralle

**Skenaario 2: Suuri operaattori (5 MW IT-kuorma)**
- Valinta: Online UPS eko-tilassa
- Perustelu: 0 ms vaihtaika, skaalautuvuus, 98% hyötysuhde eko-tilassa
- Kompromissi: Kalliimpi investointi

**Skenaario 3: Hyperscale-datakeskus (50+ MW)**
- Valinta: Hybridijärjestelmä (lyhyet akut + nopeat generaattorit + mahdollisesti vaihtovirta-ratkaisu)
- Perustelu: Halvin TCO, räätälöity ratkaisu
- Kompromissi: Vaatii huippuosaamista

### Yhteys muuhun ketjuun

UPS-valinta vaikuttaa:
- **Jäähdytykseen**: 5-10% häviöt muuttuvat lämmöksi → mitoittaa jäähdytys
- **Lattia-alaan**: Akustojen koko → tilantarve
- **Huoltoon**: Akuston vaihtoväli ja työläys
- **PUE:hen**: Jokainen häviöprosentti nostaa PUE:ta

---

## P5.3 IT-infrastruktuuri: Käyttöasteen taika

### Miksi käyttöaste on niin tärkeä?

Palvelimen energiankulutus ei ole lineaarinen:

```
Palvelimen kuorma vs. sähkönkulutus:
  0% kuorma → 150W (idle, "tyhjäkäynti")
 25% kuorma → 200W
 50% kuorma → 280W
 75% kuorma → 370W
100% kuorma → 450W
```

**Tehokkuus per työ**:
- 25% kuormalla: 200W ÷ 25 = 8 W per prosenttiyksikkö
- 75% kuormalla: 370W ÷ 75 = 4,9 W per prosenttiyksikkö

**Johtopäätös**: Palvelin on **40% tehokkaampi** 75% kuormalla kuin 25% kuormalla!

### Case: Virtualisoinnin ROI

**Ennen virtualisointia:**
- 100 fyysistä palvelinta
- Keskimääräinen kuormitus: 15%
- Energiankulutus: 100 × 200W = 20 kW
- Tehoton: Suuri osa energiasta menee idle-tilaan

**Virtualisoinnin jälkeen:**
- 30 fyysistä palvelinta
- Keskimääräinen kuormitus: 65%
- Energiankulutus: 30 × 320W = 9,6 kW
- **Säästö: 52% energiasta**

Lisäksi:
- Vähemmän jäähdytettävää → pienempi jäähdytystarve
- Vähemmän laitteita → vähemmän huoltoa
- Tiiviimpi → vähemmän lattia-alaa

### Tallennuksen piilokustannus

Levyjärjestelmät ovat usein unohdettu energiasyöppö:

**Esimerkki: 1 PB (petatavu) tallennusta**

| Ratkaisu | Laitteet | Energiankulutus | Vuosikustannus (0,10 €/kWh) |
|----------|----------|------------------|------------------------------|
| **Perinteiset HDD:t** | 2000 levyä | 15 kW | 13 140 € |
| **Tiered storage** (hot SSD + cold HDD) | 500 SSD + 1000 HDD | 8 kW | 7 008 € |
| **Erasure coding** (vähemmän redundanssia) | 1200 levyä | 9 kW | 7 884 € |

**Vihreä valinta**: Yhdistä tiered storage ja erasure coding → 5-6 kW, ~5 000 €/vuosi

---

## P5.4 Jäähdytys: Dynaaminen optimointi

### Perinteinen vs. älykäs jäähdytys

**Perinteinen lähestymistapa:**
```
1. Aseta salin lämpötilaksi 20°C
2. Aja jäähdytystä täydellä teholla aina
3. Toivo parasta
```

**Älykäs lähestymistapa:**
```
1. Aseta lämpötila-alue: 24-27°C (ASHRAE-suositukset)
2. Mittaa jatkuvasti:
   - Jokaisen räkin inlet-lämpötila
   - Ulkoilman lämpötila ja kosteus
   - IT-kuorma reaaliajassa
3. Optimoi jatkuvasti:
   - Vapaajäähdytys kun mahdollista
   - Paikallinen jäähdytyksen tehostus kuumissa pisteissä
   - Kokonaisteho minimiin
```

### Case: Suomen datakeskus talvella

**Tilanne**: Tammikuu, ulkolämpötila -15°C

**Perinteinen ratkaisu:**
- Kompressorijäähdytys täydellä teholla
- Energiankulutus: 500 kW jäähdytykseen

**Optimoitu ratkaisu:**
1. Vapaajäähdytys 100% käytössä
2. Ei kompressorien tarvetta
3. Vain pumppaus ja puhaltimet: 50 kW
4. **Säästö: 90% jäähdytysenergiasta**

**Lisäoptimi**: Nosta salin lämpötila 27°C → vielä parempi vapaan jäähdytyksen hyötysuhde

### Kuumien pisteiden hallinta

**Ongelma**: Yksi räkki vetää 30 kW, muut 5-10 kW. Kuuma piste muodostuu.

**Huono ratkaisu**: Lasketaan koko salin lämpötila → turhaa jäähdytystä

**Hyvä ratkaisu**: 
1. Paikallinen jäähdytyksen tehostus (säätöpellit, row-based cooling)
2. TAI siirrä osa työkuormasta muille palvelimille
3. TAI käytä nestejäähdytystä vain kyseiselle räkille

---

## P5.5 Verkko: Näkymätön mutta tärkeä

### Verkon energiankulutus kontekstissa

Vaikka verkko kuluttaa vain 5-10% kokonaisenergiasta, sen **välillinen vaikutus** on suuri:

**Suora vaikutus:**
- Kytkimet, reitittimet: ~500 kW (5 MW datakeskuksessa)

**Välillinen vaikutus:**
- Huono verkko → pakettihäviöt → uudelleenlähetykset → palvelimet tekevät turhaa työtä
- Tehoton verkko → viiveet → asiakkaat odottavat → palvelimet idle-tilassa pidempään
- Verkkoruuhkat → työkuormat eivät siirry optimaalisesti → huono käyttöaste

### Verkkoarkkitehtuurin valinta

**Kolmikerrosarkkitehtuuri (perinteinen):**
```
Internet
   ↓
Core-kytkimet (ydin)
   ↓
Distribution-kytkimet (jakelu)
   ↓
Access-kytkimet (reuna)
   ↓
Palvelimet
```
- Monia laitteita → enemmän energiaa
- Epäsymmetriset reitit → pullonkauloja

**Leaf-Spine (moderni):**
```
Internet
   ↓
Spine-kytkimet (selkäranka)
   ↙ ↓ ↘
Leaf-kytkimet (lehdet)
   ↓  ↓  ↓
Palvelimet
```
- Vähemmän laitteita → vähemmän energiaa
- Tasalaatuiset reitit → tehokkaampi liikenne
- **Bonus**: Helpompi skaalata

---

## P5.6 Hukkalämmön talteenotto: Taloudellinen laskenta

### Milloin talteenotto kannattaa?

**Peruskysymykset:**

1. **Onko lämmölle käyttöä?**
   - Kaukolämpöverkko lähistöllä?
   - Oma kiinteistö lämmitettävänä?
   - Kasvihuone, uima-allas, teollisuusprosessi?

2. **Mikä on lämpötilavaatimus?**
   - Matalalämpöverkko (50-60°C): Helpompi
   - Korkeatemperatuuriverkko (80-90°C): Vaatii lämpöpumpun

3. **Mikä on käyttöaika?**
   - Ympärivuotinen: Paras ROI
   - Vain talvella: Heikompi ROI
   - Satunnainen: Ei ehkä kannata

### Esimerkkikalkyyli: Kaukolämpö Suomessa

**Lähtötiedot:**
- Datakeskus: 5 MW IT-kuorma
- Hukkalämpö: ~5 MW (olettaen PUE 2.0, todellisuudessa vähemmän jäähdytyksen hyötysuhteiden vuoksi)
- Talteenotto: 3 MW (60% hukkalämmöstä)
- Käyttöaika: 6000 h/vuosi (enimmäkseen talvi)

**Investointi:**
- Lämmönvaihtimmet: 200 000 €
- Lämpöpumput: 800 000 €
- Putkistot ja liitokset: 500 000 €
- **Yhteensä: 1 500 000 €**

**Tuotot:**
- Talteenotettu energia: 3 MW × 6000 h = 18 000 MWh/vuosi
- Myyntihinta kaukolämpöön: 40 €/MWh
- **Vuositulo: 720 000 €**

**Takaisinmaksuaika: 2,1 vuotta**

**Lisähyödyt:**
- Vähentää kaukolämpöverkon fossiilista tuotantoa
- Parantaa datakeskuksen imagoa
- Mahdollistaa korkeammat salilämpötilat (parempi PUE)

### Case: Lämpöpumpun COP käytännössä

**Tilanne**: Datakeskuksen jäähdytysvesi 30°C, kaukolämpö vaatii 75°C

**Lämpötilanosto**: 45°C

**Lämpöpumpun COP**: ~3,5 (eli 1 kW sähköä → 3,5 kW lämpöä)

**Energiatase:**
- Talteenotettu lämpö datakeskuksesta: 2,5 MW
- Lämpöpumpun käyttämä sähkö: 0,7 MW
- **Kaukolämpöön syötetty lämpö: 3,2 MW**

**Kokonaishyöty**: Alkuperäisestä 5 MW IT-kuormasta saadaan 3,2 MW hyödyllistä lämpöä = **64% hyötysuhde**

---

## P5.7 Mittaus ja ohjaus: Dataan perustuva päätöksenteko

### Mittaustasojen hierarkia

**Taso 1: Kokonaistaso (pakollinen)**
- Kokonaissähkönkulutus
- IT-laitteiden kulutus
- PUE-luku

**Taso 2: Järjestelmätaso (suositeltu)**
- Jäähdytyksen kulutus
- UPS-häviöt
- Valaistus ja muu infrastruktuuri

**Taso 3: Laitetaso (optimaalinen)**
- Räkkikohtainen kulutus
- Yksittäisten palvelimien kulutus
- Verkkolaitteiden kulutus

**Taso 4: Palvelutaso (huippuluokka)**
- Energiankulutus per palvelu
- Energiankulutus per asiakas
- Energiankulutus per tapahtuma

### Mitä mittausdatalla tehdään?

**1. Reaaliaikainen valvonta**
```
Jos PUE > 1.5:
  → Hälytys operaattorille
  → Automaattinen diagnostiikka: Mikä muuttui?
  → Korjaava toimenpide
```

**2. Ennakoiva huolto**
```
Jos jäähdytyksen teho kasvaa hitaasti viikkojen aikana:
  → Todennäköisesti ilmansuodattimet tukkeutuneet
  → Ajoita suodattimien vaihto
  → Vältä kriittinen tilanne
```

**3. Kapasiteettisuunnittelu**
```
Mittaa kuukausittain:
  - Käyttöasteet palvelimittain
  - Lämpötilat räkeittäin
  - Jäähdytysteho vyöhykkeittäin

→ Tunnista missä on vapaata kapasiteettia
→ Sijoita uudet palvelimet optimaalisesti
```

**4. Taloudellinen optimointi**
```
Sähkön hinta vaihtelee tunnittain (pörssisähkö)

Älykäs ohjaus:
  - Raskas laskenta halpoina tunteina
  - Kevyt palvelu kalliina tunteina
  - Akut/UPS sähkömarkkinoiden tasapainottamiseen

→ Säästöt voivat olla 10-20% sähkölaskusta
```

### Case: Tekoälyn käyttö optimoinnissa

**Perinteinen ohjaus:**
- Säädä jäähdytystä kun lämpötila ylittää 26°C
- Ennalta määrätyt säännöt

**Tekoälypohjainen ohjaus:**
1. **Ennustus**: Sääennuste + kuormaennuste → ennakoi tarpeet 6-24h eteenpäin
2. **Optimointi**: Laske optimaalinen jäähdytysstrategia huomioiden:
   - Energian hinta
   - Ulkoilman olosuhteet
   - Odotettu IT-kuorma
   - Lämmön myyntimahdollisuus
3. **Säätö**: Ohjaa jäähdytystä, kuormitusta ja lämmön talteenottoa yhdessä

**Tulokset** (Googlen raportti):
- 40% vähemmän jäähdytysenergiaa
- 15% parempi kokonais-PUE
- 30% vähemmän operaattoriaikaa

---

## P5.8 Kokonaisoptimi: Järjestelmäajattelu

### Miksi paikallinen optimointi ei riitä?

**Esimerkki 1: Jäähdytyksen ja palvelimien ristiriita**

Optimoidaan jäähdytys erikseen:
- Lasketaan salilämpötila 20°C → PUE paranee 0.05

Mutta:
- Palvelimien tuulettimet joutuvat pyörimään hitaammin → häviöt pienenevät
- **Kokonaishyöty**: PUE paranee 0.03 (ei 0.05)

Optimoidaan yhdessä:
- Nostetaan salilämpötila 27°C
- Palvelimien tuulettimet pyörivät optimaalisesti
- Vapaajäähdytys tehokkaampaa
- **Kokonaishyöty**: PUE paranee 0.15

**Opetus**: Optimoi järjestelmää, ei komponentteja.

### Kokonaisoptimin 5 periaatetta

**1. Mittaa kokonaisuutta**
- Älä kysy "Mikä on jäähdytyksen PUE-vaikutus?"
- Kysy "Mikä on kokonais-PUE ja miten se muuttuu?"

**2. Huomioi vuorovaikutukset**
- Jokainen muutos vaikuttaa muualle
- Testaa ja mittaa todelliset vaikutukset

**3. Optimoi taloudellisesti**
- Paras PUE ei ole aina edullisin
- Huomioi investoinnit, käyttökustannukset, riskit

**4. Ajattele elinkaarta**
- Ratkaisu joka on hyvä nyt, voi olla huono 5 vuoden päästä
- Suunnittele joustavuus ja päivitettävyys

**5. Ota käyttäjät mukaan**
- Palvelun käyttäjät voivat optimoida omaa toimintaansa
- Esim. "Tämä laskenta kuluttaa 10x energiaa, haluatko ajaa sen yöllä?"

### Viitekehys kokonaisoptimointiin

```
STRATEGIA
   ↓
Mitä palveluita tarjotaan? Millä palvelutasolla?
   ↓
ARKKITEHTUURI
   ↓
Millainen infrastruktuuri tarvitaan?
   ↓
TOTEUTUS
   ↓
Miten rakennetaan energiatehokkaasti?
   ↓
OPEROINTI
   ↓
Miten ajetaan optimaalisesti?
   ↓
MITTAUS
   ↓
Saavutetaanko tavoitteet?
   ↓
JATKUVA PARANTAMINEN
   ↓
Palataan STRATEGIAAN, päivitetään tarpeen mukaan
```

---

## P5.9 Yhteenveto: Vihreän datakeskuksen päivittäinen käyttö

Tämä luku on osoittanut, että vihreä datakeskus ei ole staattinen rakennelma, vaan **jatkuvasti mukautuva järjestelmä**.

### Keskeiset oivallukset

1. **Käyttöaste on kuningas**: 75% kuormalla oleva palvelin on 40% tehokkaampi kuin 25% kuormalla oleva
   
2. **Jäähdytys on dynaaminen**: Älä aseta 20°C ja unohda, vaan optimoi jatkuvasti 24-27°C alueella

3. **Verkko on näkymätön vaikuttaja**: Huono verkko voi pilata muiden optimoinnit

4. **Hukkalämpö on resurssi**: Oikeissa olosuhteissa takaisinmaksuaika 2-3 vuotta

5. **Mittaus mahdollistaa kaiken**: Ilman dataa optimointi on arvailua

6. **Tekoäly auttaa mutta ei korvaa**: Hyvä suunnittelu ja operointi ovat perusta

### Seuraavat askeleet

Jos haluat parantaa datakeskuksesi vihreyttä:

**Vaihe 1: Mittaa nykytila**
- Laske todellinen PUE (vuositasolla)
- Tunnista suurimmat energiasyöpöt
- Mittaa käyttöasteet

**Vaihe 2: Poimi matala-roikkuvat hedelmät**
- Virtualisoi ja konsolidoi palvelimia
- Nosta salilämpötila ASHRAE-suositusten ylärajalle
- Ota vapaajäähdytys käyttöön

**Vaihe 3: Systeemioptimoint**
- Tekoälypohjainen jäähdytyksen ohjaus
- Dynaamiset työkuormat (siirrä kuormaa ajan ja paikan mukaan)
- Integroitu mittaus ja ohjaus

**Vaihe 4: Ekosysteemi**
- Hukkalämmön myynti
- Osallistuminen sähkömarkkinoille
- Uusiutuvan energian ostosopimukset

---

**Seuraava luku (P6)** käsittelee datakeskuksen valvontaa ja hallintaa syvemmin, erityisesti sitä miten automaatiojärjestelmät ja henkilöstö työskentelevät yhdessä vihreän toiminnan varmistamiseksi.
