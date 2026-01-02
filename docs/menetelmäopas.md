# M – Menetelmäopas: konesalin toiminnan hiilijalanjäljen optimointi mittausdatan avulla

## M0. Tarkoitus ja periaate

Soveltamisala. Tämä opas koskee vihreän datakeskuksen (oma DC tai colocation) sähkö–IT–jäähdytys–hukkalämpö -ketjun mitattavuutta, raportointia ja todennettavuutta, jotta energiatehokkuus (PUE) ja muut vihreysvaatimukset eivät jää väitteiksi vaan voidaan osoittaa datalla. [2][4][6][7][9]

Toteutusperiaate. PUE:n laskenta ja johtaminen edellyttävät vähintään kokonaisenergian ja IT-energian erottelua; lisäksi UPS-häviöt ja jäähdytyksen energia tulee pystyä osoittamaan osajärjestelmätasolla, jotta optimoinnin kohde on yksiselitteinen ja todennettavissa. [2][6][7]

**Tarkoitus.** Tämä menetelmäopas kuvaa, miten datakeskuksen operatiivinen hiilijalanjälki (energia → CO₂e) **mitataan, todennetaan ja pienennetään** mittausdatan avulla siten, että muutos voidaan osoittaa “ennen–jälkeen”-vertailuna. Menetelmä perustuu jatkuvaan silmukkaan: **mittaa → analysoi → muuta → todenna → vakioi**. [2][4]

**Ydinajatus.** Datakeskuksessa kaikki IT:n käyttämä sähkö päätyy lopulta lämmöksi, joten hiilijalanjäljen optimointi on koko ketjun optimointia (sähkö → IT → verkko → jäähdytys → lämpö → mittaus). [1][6][7]

---

## M1. Rajaus (mitä mitataan ja mistä CO₂e syntyy)

### M1.1 Operatiivisen hiilijalanjäljen rajat (käyttövaihe)
Menetelmä kattaa datakeskuksen käyttöaikaisen toiminnan:
- **Sähkön kulutus**: IT-laitteet + jäähdytys + sähköketjun häviöt + muu infrastruktuuri. [6][7]
- **Hukkalämmön talteenotto ja toimitus** (jos käytössä): mitataan toimitettu lämpöenergia erikseen. [7][9]
- (Valinnainen laajennus) **Varavoiman testiajot ja poikkeamat** sekä mahdolliset energianvarastot osana energianhallintaa. [3][6]

> Huom: menetelmäoppaassa raportoidaan CO₂e **ensisijaisesti mitatun energian perusteella**; muut päästölähteet lisätään vain, jos data on todennettavissa (audit trail). [2][4]

### M1.2 Mitkä KPI:t ovat pakollisia
Pakollinen ydin:
- **E_total (kWh)**: koko laitoksen energia (sisään tuleva). [6][7]
- **E_IT (kWh)**: IT-laitteiden energia (PDU/räkki tai vastaava). [6][7]
- **PUE** = E_total / E_IT. [2][4]
- **CO₂e**: E_total (tai eritelty E_total) × päästökerroin (raportointiperiaate). [2][9]

Suositeltu täydentävä:
- **E_cooling (kWh)** ja jäähdytyksen osuus. [4][7]
- **UPS-häviöt (kWh)**: UPS_in − UPS_out. [6][7]
- **Lämpöenergian toimitus (MWh_th)**: toimitettu hukkalämpö, jos myydään/siirretään. [7][9]
- **Verkon energia (kWh)** suhteessa liikenteeseen, jos erotettavissa. [8]

---

## M2. Vaaditut dokumentit (mitä “pitää olla olemassa” ennen kuin optimointi on tieteellisesti todennettavaa)

Alla olevat ovat menetelmän “todisteaineistoa”. Ilman näitä mittausdatan tulkinta jää epävarmaksi. [2][4][7]

### M2.1 Pakolliset dokumentit (minimi)
1) **Mittauspistekartta (Instrumentation & Metering Map)**  
   - mitä mitataan, missä tasossa (sisään tuleva energia, UPS, PDU/räkki, jäähdytys, lämpötoimitus) ja mittareiden yksilöinti. [6][7]  
2) **KPI-määrittelyt ja laskentasäännöt**  
   - PUE (laskenta, ajanjaksotus), CO₂e (päästökerroinperiaate), mahdollinen lämpöenergia (MWh_th). [2][4]  
3) **Datan omistajuus ja saatavuus (Data Access & Ownership)**  
   - kuka omistaa mittausdatan, miten se toimitetaan, miten audit trail säilyy. [2][4]  
4) **Commissioning / hyväksyntäpöytäkirja mittaukselle**  
   - todennus, että mittarit mittaavat oikein ja data kulkee järjestelmiin (end-to-end). [4][7]

### M2.2 Suositeltavat dokumentit (parantaa optimoinnin laatua)
5) **Sähköketjun single-line diagram + häviöerittely** (muuntajat–UPS–jakelu). [6][7]  
6) **Jäähdytysjärjestelmän prosessikaaviot + ohjausperiaatteet** (setpointit, ohjauslogiikka). [4][7]  
7) **Kuormaprofiili ja palvelutaso (SLA) + kapasiteettipolitiikat** (IT-ohjauksen perusteet). [1][2]  
8) **Verkon energiaprofiili ja liikenneprofiilit** (jos halutaan optimoida myös verkkoa). [8]

**Käytännössä: mistä nämä saa? (ICT-yrityksen lukijalle)**
- Jos olet **datakeskuksen asiakas (colocation/pilvi)**: pyydä operaattorilta kohdat 1–4 osana “sustainability data pack” -liitettä sopimukseen.
- Jos olet **rakentaja/omistaja**: tilaa kohdat 1–2 suunnittelijalta ja varmista kohta 4 käyttöönoton (commissioning) sopimuksessa. [4][7]
- Jos olet **IT-palveluomistaja**: omistat usein kohdan 7 ja vaikutat 8:aan (traffic & workload). [1][8]

---

## M3. Minimitasot (Basic / Standard / Advanced) – millä tasolla optimointi on mahdollista

### Basic (riittää PUE + CO₂e per kuukausi)
- Mittaus: E_total (sisään tuleva), E_IT (PDU/räkki tai vastaava), UPS_in/UPS_out (suositeltu). [6][7]
- Raportointi: PUE kuukausi- ja viikkotasolla, CO₂e kuukausitasolla. [2][9]

### Standard (riittää ohjaukseen ja “muutos → vaikutus” -todennukseen)
- Lisäksi: E_cooling eritelty, lämpötila/ΔT per sali/alue, perusvirtaamat tai indikaattorit. [4][7]
- Raportointi: PUE + jäähdytysosuus + UPS-häviöt; CO₂e viikko-/päivätasolla. [2][4]

### Advanced (riittää jatkuvaan optimointiin ja automaatioon)
- Lisäksi: vyöhykekohtainen mittaus (sähkö + jäähdytys), verkon energia, lämpötoimituksen reaaliaikainen mittaus, datan laatuindikaattorit. [4][8]
- Mahdollistaa: kuorman ja jäähdytyksen yhteisoptimoinnin (dynaaminen ohjaus) ja poikkeamien automaattisen havaitsemisen. [1][3][4]

---

## M4. Todennukset (miten varmistetaan, että tulokset ovat “audit-kelpoisia”)

### M4.1 Mittauksen todennus (pakollinen)
**End-to-end todennus (“mittari → data → KPI”).**  
Tarkista vähintään:
- Mittarien kalibrointi/luokka + aikaleimat.
- E_total ja E_IT järkevä suhde (PUE realistinen).
- UPS_in ja UPS_out tuottavat johdonmukaiset häviöt. [6][7]

**Tuotos:** “Measurement SAT” -pöytäkirja + poikkeamalista. [4][7]

### M4.2 Datan laadun todennus (jatkuva)
- Datakatkot, epärealistiset hyppäykset, drift.
- Sensorien “hiljainen vika” (arvo jäätyy).
- KPI:n laskenta ei saa muuttua ilman versionhallittua muutosta. [2][4]

**Tuotos:** Datan laaturaportti (viikko/kk) + korjaustoimet. [2][4]

### M4.3 Optimoinnin todennus (“ennen–jälkeen”)
Jokaiselle muutokselle:
- lähtötaso (baseline), muutos, mittausjakso, vaikutus KPI:hin, riskit/SLA. [4]
- Hyväksyntä vasta kun vaikutus on mitattu eikä pelkästään oletettu. [2][4]

---

## M5. Mittausdata → CO₂e-laskenta (miten hiilijalanjälki tuotetaan datasta)

### M5.1 Peruslaskenta
- Laske ajanjaksolle: **E_total**, **E_IT**, **PUE**. [2][4]
- Laske CO₂e ajanjaksolle:  
  - **CO₂e_total = E_total × EF_electricity** (raportointiperiaatteen mukainen päästökerroin). [9]
- Raportoi erikseen (suositus):  
  - CO₂e_total ja sen osatekijät (IT vs jäähdytys vs häviöt), jos erittely on mitattavissa. [2][4][7]

### M5.2 Hukkalämmön mittaus (ei “arvio”, vaan mitattu energia)
- Mittaa toimitettu lämpöenergia (MWh_th) ja lämpötaso (lähtö/paluu), jos lämmönvaihto/lämpöpumppu käytössä. [7][9]
- Raportoi lämpö **erillisenä hyötymittarina**, ei automaattisena vähennyksenä CO₂e:stä (ellei laskentasääntö ole eksplisiittisesti sovittu ja auditoitavissa). [9]

---

## M6. Optimointimenetelmä (mistä CO₂e vähenee käytännössä)

Tässä menetelmä kytkeytyy suoraan toimintaketjuun: sähkö → IT → verkko → jäähdytys → lämpö. [1][6][7]

### M6.1 IT-kuorman optimointi (energia per palvelu)
- Konsolidointi ja virtualisointi: vähemmän aktiivisia palvelimia samalla SLA:lla. [1][2]
- Tehonhallinta ja kuorman sijoittelu: energiaproportionaali toiminta, vähemmän tyhjäkäyntiä. [1][2]

**Todennus:** E_IT laskee tai palveluyksikkö/energia paranee, SLA säilyy. [1][2]

### M6.2 Verkon optimointi (liikenne per energia)
- Mittaa liikenne ja sovita linkit/laitteet kuormaan (SLA-rajoissa). [8]

**Todennus:** verkon kWh laskee tai kWh/GB paranee ilman latenssi-/häiriöpiikkiä. [8]

### M6.3 Jäähdytyksen optimointi (lämmön poisto pienemmällä energialla)
- Setpointit, ilmavirrat/containment, vapaajäähdytyksen hyödyntäminen (Suomi). [4][7]
- Ohjauslogiikka: jäähdytys reagoi kuormaan, ei “vakioasetuksilla”. [4]

**Todennus:** E_cooling pienenee, hotspotit eivät kasva, PUE paranee. [4][7]

### M6.4 Hukkalämmön hyötykäytön optimointi (korvaava energia)
- Vakioi lämpöteho ja lämpötaso niin, että hyötykäyttö on luotettava (sopii vastaanottajalle). [7][9]

**Todennus:** toimitettu MWh_th kasvaa / vakaantuu ja on mitattu. [7][9]

M6.5 Reaaliaikainen valvonta ja AI/DA-ohjaus (miten se tehdään todennettavasti)

Rakenna se näin (tiiviinä):

Mitä mitataan reaaliajassa (viittaus M1/M2 mittapisteisiin)

Mitä AI optimoi (ohjausmuuttujat)

Mitä rajoitteita ei saa rikkoa (SLA, lämpöraja, redundanssi)

Miten vaikutus todennetaan (M4.3 before–after + versionhallinta)

Näin AI/DA ei jää “maininnaksi”, vaan se on menetelmään kytketty osa, jonka vaikutus voidaan osoittaa.


---

## M7. Mitä asiakkaana saat ulos (API/raportti) – vähimmäisvaatimus

M7 on “sustainability data pack” -liite, jonka colocation-asiakas voi vaatia sopimukseen.

Datan tulee tulla sekä raporttina että koneellisesti (CSV/JSON/API) ja sisältää myös data quality -kentät (missing %, aikaleimat).

KPI-laskenta ei saa muuttua ilman versionhallintaa (sinulla tämä on jo M4.2:ssa — nosta se näkyväksi myös M7:ään).


### M7.1 Pakollinen asiakasraportti (kuukausi + tiivistelmä)
Raportti sisältää vähintään:
- E_total (kWh), E_IT (kWh), PUE.
- CO₂e_total (kgCO₂e) + käytetty EF-periaate (mistä päästökerroin tulee).
- UPS-häviöt (kWh) jos mitattu.
- (Jos lämpötoimitus) Toimitettu lämpö (MWh_th) + mittauspiste ja ajanjakso. [2][6][7][9]

### M7.2 Pakollinen API-minimi (jos asiakas haluaa koneellisesti)
Minimissä API tarjoaa aikajanan (päivä/viikko) seuraaville:
- total_energy_kwh
- it_energy_kwh
- pue
- co2e_kg
- (optional) cooling_energy_kwh, ups_losses_kwh, heat_export_mwh_th

**Esimerkkirakenne (JSON):**
```json
{
  "period": "2026-01",
  "site_id": "DC-FI-001",
  "metrics": {
    "total_energy_kwh": 1234567,
    "it_energy_kwh": 1023456,
    "pue": 1.21,
    "co2e_kg": 45678,
    "ups_losses_kwh": 23456,
    "cooling_energy_kwh": 167890,
    "heat_export_mwh_th": 1200.5
  },
  "calculation_rules": {
    "pue": "total_energy_kwh / it_energy_kwh",
    "co2e": "total_energy_kwh * EF",
    "ef_note": "EF-periaate dokumentoitu raportissa"
  },
  "data_quality": {
    "missing_data_pct": 0.2,
    "timestamp_quality": "ok"
  }
}

