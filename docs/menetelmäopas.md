
# M – Menetelmäopas: konesalin toiminnan hiilijalanjäljen optimointi mittausdatan avulla

## M0. Tarkoitus ja periaate

### M0.1 Soveltamisala (mitä tämä opas kattaa)

Tämä menetelmäopas koskee vihreän datakeskuksen (oma DC tai colocation) **sähkö–IT–jäähdytys–hukkalämpö**-ketjun **mitattavuutta, raportointia ja todennettavuutta**, jotta energiatehokkuus (PUE) ja muut vihreysvaatimukset eivät jää väitteiksi vaan voidaan osoittaa datalla. [2][4][6][7][9][11]

### M0.2 Toteutusperiaate (mikä on “pakko olla totta”, jotta optimointi on todennettavaa)

PUE:n laskenta ja johtaminen edellyttävät vähintään **kokonaisenergian (E_total)** ja **IT-energian (E_IT)** erottelua. Lisäksi **UPS-häviöt** ja **jäähdytyksen energia** tulee pystyä osoittamaan osajärjestelmätasolla, jotta optimointikohde on yksiselitteinen ja muutos voidaan todentaa “ennen–jälkeen”. [2][4][6][7]

### M0.3 Menetelmän silmukka (mitä tehdään aina samalla tavalla)

Menetelmä perustuu jatkuvaan silmukkaan: **mittaa → analysoi → muuta → todenna → vakioi**. [2][4]
Ydinajatus on, että datakeskuksessa **kaikki IT:n käyttämä sähkö päätyy lopulta lämmöksi**, joten hiilijalanjäljen optimointi on koko ketjun optimointia (sähkö → IT → verkko → jäähdytys → lämpö → mittaus). [1][6][7]

---

## M1. Rajaus (mitä mitataan ja mistä CO₂e syntyy)

### M1.1 Operatiivisen hiilijalanjäljen rajat (käyttövaihe)

Menetelmä kattaa datakeskuksen käyttöaikaisen toiminnan:

* **Sähkön kulutus**: IT-laitteet + jäähdytys + sähköketjun häviöt + muu infrastruktuuri. [6][7]
* **Hukkalämmön talteenotto ja toimitus** (jos käytössä): mitataan toimitettu lämpöenergia erikseen. [7][9]
* (Valinnainen) **Varavoiman testiajot/poikkeamat** sekä mahdolliset energianvarastot energianhallinnan osana. [3][5][6]

> Huom: CO₂e raportoidaan **ensisijaisesti mitatun energian perusteella**; muut päästölähteet lisätään vain, jos data on todennettavissa (audit trail). [2][4]

### M1.2 Pakolliset KPI:t (minimivaatimus)

Pakollinen ydin:

* **E_total (kWh)**: koko laitoksen sisään tuleva energia (määritelty mittausrajalla). [6][7]
* **E_IT (kWh)**: IT-laitteiden energia (PDU/räkki tai vastaava). [6][7]
* **PUE = E_total / E_IT**. [2][4]
* **CO₂e_total (kgCO₂e)**: E_total × päästökerroin (raportointiperiaate dokumentoitu). [2][9][20]

Suositeltu täydentävä (nostaa optimoinnin laatua):

* **E_cooling (kWh)** + jäähdytyksen osuus. [4][7]
* **UPS-häviöt (kWh)**: UPS_in − UPS_out. [6][7]
* **Lämpöenergian toimitus (MWh_th)** + lämpötaso (L1/L2, lähtevä/paluu). [7][9]
* **Verkon energia (kWh)** suhteessa liikenteeseen, jos erotettavissa. [8]

---

## M2. Vaaditut dokumentit (todisteaineisto) + mistä ne saat käytännössä

Alla olevat ovat menetelmän “todisteaineistoa”. Ilman niitä mittausdatan tulkinta jää epävarmaksi ja “optimointi” muuttuu helposti arvaukseksi. [2][4][7]

### M2.1 Pakolliset dokumentit (minimi, *pakko olla olemassa*)

1. **Mittausrajaus (Measurement Boundary Statement)**

   * missä E_total mitataan (verkko/kiinteistöliityntä), mitä sisältyy ja mitä ei (esim. toimistotilat, ulkoiset laitteet). [2][4][7]
2. **Mittauspistekartta (Instrumentation & Metering Map)**

   * mittauspisteet, mittarityypit/luokka, mittarien tunnisteet, mittausväli ja datan reitti (mittari → järjestelmä → tallennus). [6][7]
3. **KPI-määrittelyt ja laskentasäännöt (KPI Dictionary & Calculation Rules)**

   * PUE:n ajanjaksotus, CO₂e-laskenta (EF-periaate), UPS-häviöiden laskenta, mahdollinen lämpöenergian raportointi. [2][4][9][20]
4. **Datan omistajuus ja toimitusmuoto (Data Access & Ownership + Delivery Spec)**

   * kuka omistaa datan, mitä asiakas saa, missä formaatissa (PDF/CSV/JSON/API), aikajänne, granulariteetti, aikavyöhyke, data quality -kentät. [2][4]
5. **Mittauksen käyttöönottotodennus (Measurement SAT / Commissioning Record)**

   * end-to-end-testi: mittarit mittaavat oikein, aikaleimat oikein, data tulee perille, KPI:t täsmäävät. [4][7]

**Minimivaatimus käytännössä:** jos nämä 1–5 ovat olemassa ja kunnossa, voit tehdä **audit-kelpoisen** PUE+CO₂e-optimoinnin (Basic/Standard tason mukaan). [2][4]

### M2.2 Suositeltavat dokumentit (nostaa optimoinnin “tason” Standard/Advanced)

6. **Sähköketjun single-line diagram + häviöerittely** (muuntajat–UPS–jakelu). [6][7]
7. **Jäähdytysjärjestelmän prosessikaaviot + ohjausperiaatteet** (setpointit, ohjauslogiikka, free-cooling). [4][7]
8. **Kuormaprofiili + SLA + kapasiteettipolitiikat** (konsolidointi/right-sizing, tehorajat). [1][2][16]
9. **Verkon liikenne- ja energiaprofiilit** (jos optimoidaan myös verkkoa). [8]

### M2.3 “Teenkö itse vai saanko jostain?” (roolipohjainen ohje)

* Jos olet **colocation-asiakas**: vaadi operaattorilta **1–5** osana sopimusliitettä (“Sustainability Data Pack”). Älä tyydy pelkkään PUE-lukuun ilman mittauspistekarttaa ja laskentasääntöjä. [2][4][7]
* Jos olet **DC-omistaja/rakentaja**: tilaa **2, 6, 7** suunnittelijalta; vaadi **5** käyttöönoton urakkaan (commissioning). [4][7]
* Jos olet **IT-palveluomistaja**: omistat tyypillisesti **8** (SLA/kuormapolitiikat) ja vaikutat **9** (verkko/traffic). [1][8][16]

---

## M3. Minimitasot (Basic / Standard / Advanced) – millä tasolla optimointi on oikeasti mahdollista

### Basic (riittää PUE + CO₂e kuukausitasolla, audit-kelpoinen minimi)

**Mittauspaketti**

* E_total (sisään tuleva), E_IT (PDU/räkki), (suositus) UPS_in/UPS_out. [6][7]
  **Granulariteetti**
* vähintään **1 h** aikaväli (tai tiheämpi), kuukausiraportointi. [2][4]
  **Tuotos**
* PUE (kk ja viikko), CO₂e (kk) + EF-periaate kirjattuna. [2][9][20]

### Standard (riittää ohjaukseen ja “muutos → vaikutus” -todennukseen)

**Lisäksi**

* E_cooling eritelty + lämpötila/ΔT vähintään sali/alue tasolla + perusvirtaama-indikaattorit. [4][7]
  **Granulariteetti**
* suositus **15 min** aikaväli (päivä/viikko trendit). [4][7]
  **Tuotos**
* PUE + jäähdytysosuus + UPS-häviöt; CO₂e viikko-/päivätasolla. [2][4][7]

### Advanced (riittää jatkuvaan optimointiin ja automaatioon/AI-ohjaukseen)

**Lisäksi**

* vyöhykekohtainen sähkö + jäähdytys, lämpötoimituksen reaaliaikainen mittaus, datan laatuindikaattorit, (opt.) verkon energia. [4][8]
  **Granulariteetti**
* suositus **5 min** aikaväli tai tiheämpi. [4]
  **Mahdollistaa**
* kuorman + jäähdytyksen yhteisoptimoinnin, poikkeamien automaattisen havaitsemisen ja mallipohjaisen ohjauksen. [1][3][4][16]

---

## M4. Todennukset (miten tuloksista tehdään audit-kelpoisia)

### M4.1 Mittauksen todennus (pakollinen, ennen optimointia)

**End-to-end (“mittari → data → KPI”)**:

* mittarien luokka/kalibrointi + aikaleimat
* E_total ja E_IT tuottavat realistisen PUE-alueen
* UPS_in ja UPS_out tuottavat johdonmukaiset häviöt. [6][7]

**Tuotos:** Measurement SAT -pöytäkirja + poikkeamalista + korjaustoimet. [4][7]

### M4.2 Datan laadun todennus (jatkuva)

* datakatkot, epärealistiset hyppäykset, drift
* “hiljainen vika” (arvo jäätyy)
* KPI-laskenta ei saa muuttua ilman versionhallittua muutosta. [2][4]

**Tuotos:** Datan laaturaportti (viikko/kk) + korjaustoimet. [2][4]

### M4.3 Optimoinnin todennus (“ennen–jälkeen”, aina)

Jokaiselle muutokselle:

* baseline, muutos, mittausjakso, vaikutus KPI:hin, riskit/SLA. [4]
* hyväksyntä vasta, kun vaikutus on **mitattu**, ei oletettu. [2][4]

---

## M5. Mittausdata → CO₂e-laskenta (miten hiilijalanjälki tuotetaan datasta)

### M5.1 Peruslaskenta

* Laske ajanjaksolle: E_total, E_IT, PUE. [2][4]
* Laske CO₂e: **CO₂e_total = E_total × EF_electricity**, missä EF-periaate on dokumentoitu (esim. location-based ja/tai market-based). [9][20]
* Raportoi erikseen (suositus): IT vs jäähdytys vs häviöt, jos erottelu on mitattu. [2][4][7]

### M5.2 Hukkalämmön mittaus (ei arvio)

* mittaa toimitettu lämpöenergia (MWh_th) + lämpötaso (lähtö/paluu), jos talteenotto käytössä. [7][9]
* raportoi lämpö erillisenä hyötymittarina, ellei vähennyssääntö ole eksplisiittisesti sovittu ja auditoitavissa. [9][20]

---

## M6. Optimointimenetelmä (mistä CO₂e vähenee käytännössä)

### M6.1 IT-kuorman optimointi (energia per palvelu)

* konsolidointi + virtualisointi (vähemmän aktiivisia palvelimia samalla SLA:lla). [1][2]
* right-sizing ja tehoproportionaali toiminta (vähemmän tyhjäkäyntiä). [14][16]
* idle-energian leikkaus mekanismeilla, jotka mahdollistavat oikean “sleep/idle”-käytöksen. [13]

**Todennus:** E_IT laskee tai palveluyksikkö/energia paranee, SLA säilyy. [1][2][16]

### M6.2 Verkon optimointi (liikenne per energia)

* mittaa liikenne ja sovita linkit/laitteet kuormaan SLA-rajoissa. [8]

**Todennus:** verkon kWh laskee tai kWh/GB paranee ilman latenssi-/häiriöpiikkiä. [8]

### M6.3 Jäähdytyksen optimointi (lämmön poisto pienemmällä energialla)

* setpointit, ilmavirrat/containment, free-cooling-osuuden maksimointi (Suomi). [4][7]
* ohjauslogiikka: jäähdytys reagoi kuormaan, ei “vakioasetuksilla”. [4]

**Todennus:** E_cooling pienenee, hotspotit eivät kasva, PUE paranee. [4][7]

### M6.4 Hukkalämmön hyötykäytön optimointi (korvaava energia)

* vakioi lämpöteho ja lämpötaso niin, että hyötykäyttö on luotettava vastaanottajalle. [7][9]

**Todennus:** toimitettu MWh_th kasvaa/vakaantuu ja on mitattu. [7][9]

### M6.5 Reaaliaikainen valvonta ja AI/DA-ohjaus (toteutus niin, että vaikutus voidaan todentaa)

Tässä osassa “tekoäly ja data-analyysi” sidotaan mittausketjuun ja todennukseen, eikä jätetä yleispuheeksi. [2][4]

**(1) Mitä mitataan reaaliajassa (syöte AI/DA:lle)**
Vähintään Standard-tasolla:

* E_total, E_IT, E_cooling, UPS_in/out (jos saatavilla), lämpötila/ΔT, kuormaprofiili. [4][7][16]
  Advanced-tasolla lisäksi vyöhykemittaukset ja data quality -indikaattorit. [4]

**(2) Mitä AI/DA optimoi (ohjausmuuttujat)**
Tyypilliset ohjausmuuttujat (valitse toteutettavissa olevat):

* jäähdytyksen setpointit, puhallin-/pumppunopeudet, free-cooling-tilat. [4][7]
* IT-konsolidointi/right-sizing (työkuormien sijoittelu), jolloin jäähdytyskuorma muuttuu hallitusti. [1][2][16]
* (valinnainen) kuorman ajo/siirto energia-/päästötilanteen mukaan (esim. geo-load balancing, kun SLA sallii). [15][17]

**(3) Rajoitteet joita ei saa rikkoa (turva- ja SLA-kehys)**

* SLA/viive/kapasiteettirajat (IT + verkko). [1][8]
* lämpötila- ja hotspot-rajat (jäähdytys). [4][7]
* redundanssi ja sähköketjun turvarajat (UPS/generaattori/kuormitus). [6][7]

**(4) Miten vaikutus todennetaan (ettei AI jää “mustaksi laatikoksi”)**

* jokaiselle mallille/ohjauslogiikalle: versio, käyttöönoton ajankohta, muuttujat ja rajat. [2][4]
* “ennen–jälkeen”-todennus: baseline + muutos + mittausjakso + KPI-vaikutus + SLA-seuranta. [4]
* jos AI muuttaa setpointteja: raportoi myös **E_cooling**, hotspot-mittarit ja PUE-muutos samalta jaksolta. [4][7]

**Tuotos (deliverables, AI/DA-osuudesta):**

* **AI/DA-ohjauskuvaus** (mitkä mittarit → mikä malli → mitkä ohjausmuuttujat → mitkä rajoitteet). [2][4]
* **Malliversiointi + muutosloki** (audit trail). [2][4]
* **Todennusraportti** (baseline vs jälkeen, KPI-vaikutus + SLA-ehdot). [4]

---

## M7. Mitä asiakkaana saat ulos (raportti + API/CSV) – vähimmäisvaatimus (“Sustainability Data Pack”)

Tämä on sopimusliite, jonka colocation-asiakas voi vaatia. Datan pitää tulla **sekä ihmiselle luettavana** että **koneellisesti**, ja mukana pitää olla myös laskentasäännöt sekä datan laatu. [2][4][7][9][20]

### M7.1 Pakollinen asiakasraportti (kuukausi + tiivistelmä)

Raportti sisältää vähintään:

* E_total (kWh), E_IT (kWh), PUE. [2][6][7]
* CO₂e_total (kgCO₂e) + EF-periaate (location/market, lähde ja päivitysrytmi). [9][20]
* UPS-häviöt (kWh) jos mitattu. [6][7]
* (Jos lämpötoimitus) toimitettu lämpö (MWh_th) + mittauspiste + ajanjakso + lämpötaso. [7][9]

**Pakolliset liitteet raporttiin (audit-kelpoisuus):**

* mittausrajaus + mittauspistekartta (versio). [4][7]
* KPI-sanasto ja laskentasäännöt (versio). [2][4]
* data quality -yhteenveto (missing %, poikkeamat, korjaukset). [2][4]

### M7.2 Pakollinen koneellinen toimitus (CSV/JSON/API)

**Minimivaatimus:**

* vähintään **päivä- tai viikkotaso** (Basic) ja suositus **15 min** (Standard). [4][7]
* jokaisella datapisteellä aikaleima + aikavyöhyke. [2][4]
* mukana data quality -kentät (missing %, flagit). [2][4]

**Pakolliset kentät (minimi):**

* `total_energy_kwh` (E_total)
* `it_energy_kwh` (E_IT)
* `pue`
* `co2e_kg` + `ef_method` + `ef_value` (tai viite ef-dokumenttiin)

**Suositellut lisäkentät:**

* `cooling_energy_kwh` (E_cooling)
* `ups_losses_kwh`
* `heat_export_mwh_th` + lämpötaso (jos käytössä)
* `data_quality_missing_pct`, `data_quality_flags`

**Esimerkkirakenne (JSON):**

```json
{
  "period": "2026-01",
  "site_id": "DC-FI-001",
  "timezone": "Europe/Helsinki",
  "granularity_minutes": 60,
  "metrics": {
    "total_energy_kwh": 1234567,
    "it_energy_kwh": 1023456,
    "pue": 1.21,
    "co2e_kg": 45678,
    "ef_method": "location-based",
    "ef_value_kg_per_kwh": 0.037,
    "ups_losses_kwh": 23456,
    "cooling_energy_kwh": 167890,
    "heat_export_mwh_th": 1200.5
  },
  "calculation_rules_version": "v1.3.0",
  "data_quality": {
    "missing_data_pct": 0.2,
    "flags": ["ok"]
  }
}
```

### M7.3 Todennus asiakkaalle (mitä voit pyytää “todisteeksi”)

Asiakkaana sinulla on oikeus vaatia:

* mittauksen SAT-pöytäkirja (M4.1) ja datan laadun raportti (M4.2) [4][7]
* KPI-laskentasäännöt versionumeroituna (M2.1/M4.2) [2][4]
* EF-periaate dokumentoituna (M5) [9][20]

---

# Lähteet (APA, numerointi)

[1] Jin, X., Zhang, Y., Vasilakos, A. V., & Liu, Z. (2016). *Green data centers: A survey, perspectives, and future directions*. arXiv (arXiv:1608.00687).

[2] Uddin, M., & Rahman, A. A. (2012). Energy efficiency and low carbon enabler green IT framework for data centers considering green metrics. *Renewable and Sustainable Energy Reviews, 16*(6), 4078–4094.

[3] Pierson, J.-M., Baudic, G., Caux, S., Celik, B., Costa, G., Grange, L., … Varnier, C. (2019). DATAZERO: Datacenter with zero emission and robust management using renewable energy. *IEEE Access*.

[4] Sharma, P., Pegus II, P., Irwin, D. E., Shenoy, P., Goodhue, J., & Culbert, J. (2017). Design and operational analysis of a green data center. *IEEE Internet Computing, 21*(4), 16–24.

[5] Luo, X., Wang, J., Dooner, M., & Clarke, J. (2015). Overview of current development in electrical energy storage technologies and the application potential in power system operation. *Applied Energy, 137*, 511–536.

[6] Barroso, L. A., Clidaras, J., & Hölzle, U. (2013). *The datacenter as a computer: An introduction to the design of warehouse-scale machines* (2nd ed.). Morgan & Claypool.

[7] Geng, H. (Ed.). (2014). *Data center handbook*. John Wiley & Sons.

[8] Bilal, K., Malik, S. U. R., Khalid, O., Hameed, A., Alvarez, E., Wijaysekara, V., … Khan, S. U. (2014). A taxonomy and survey on green data center networks. *Future Generation Computer Systems, 36*, 189–208.

[9] Liikenne- ja viestintäministeriö. (2020). *The ICT sector, climate and the environment – Interim report* (Publications of the Ministry of Transport and Communications 2020:14).

[10] Andrae, A. S. G., & Edler, T. (2015). On global electricity usage of communication technology: Trends to 2030. *Challenges, 6*(1), 117–157.

[11] Masanet, E., Shehabi, A., Lei, N., Smith, S., & Koomey, J. (2020). Recalibrating global data center energy-use estimates. *Science, 367*(6481), 984–986.

[12] Shehabi, A., Smith, S., Sartor, D., Brown, R., Herrlin, M., Koomey, J., Masanet, E., Horner, N., Azevedo, I., & Lintner, W. (2016). *United States data center energy usage report*. Lawrence Berkeley National Laboratory.

[13] Meisner, D., Gold, B. T., & Wenisch, T. F. (2009). PowerNap: Eliminating server idle power. In *Proceedings of the 14th International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS ’09)* (pp. 205–216). ACM.

[14] Fan, X., Weber, W.-D., & Barroso, L. A. (2007). Power provisioning for a warehouse-sized computer. In *Proceedings of the 34th Annual International Symposium on Computer Architecture (ISCA ’07)* (pp. 13–23). ACM.

[15] Qureshi, A., Weber, R., Balakrishnan, H., Guttag, J., & Maggs, B. (2009). Cutting the electric bill for internet-scale systems. In *Proceedings of the ACM SIGCOMM 2009 Conference* (pp. 123–134). ACM.

[16] Lin, M., Wierman, A., Andrew, L. L. H., & Thereska, E. (2011). Dynamic right-sizing for power-proportional data centers. In *Proceedings of IEEE INFOCOM 2011* (pp. 1098–1106). IEEE.

[17] Liu, Z., Lin, M., Wierman, A., Low, S. H., & Andrew, L. L. H. (2011). Greening geographical load balancing. In *Proceedings of the ACM SIGMETRICS 2011* (pp. 233–244). ACM.

[20] World Resources Institute (WRI) & World Business Council for Sustainable Development (WBCSD). (2015). *GHG Protocol Scope 2 Guidance: An amendment to the GHG Protocol Corporate Standard*.

---

Jos haluat, voin seuraavaksi kirjoittaa sinulle **valmiin M6.5-alaluvun “syvemmälle menevillä tutkimustuloksilla”** (AI/DA-ohjaus, mallityypit: ennusteet/anomaliat/optimointi, sekä mitä tuloksia kirjallisuus raportoi ja millä mittausvaatimuksilla ne ovat uskottavia) — mutta teen sen niin, että jokainen väite on sidottu yllä olevaan mittaus- ja todennusrunkoon (M2–M4), eikä siitä tule irrallinen “AI-kappale”.


