# Datakeskuksen sähkönkulutuksen optimointikartoitus (Q)
**Versio 2.0 – yhteensopiva Optimointioppaan O0–O6 kanssa**

Tämän kartoituksen tarkoitus on selvittää,
missä vaiheessa datakeskuksen energiatehokkuuden
mittaaminen, analytiikka ja optimointi ovat nyt.

Jokainen pääosio vastaa Optimointioppaan lukua:

- Q0 → O0–O1 (tausta ja tavoitteet)
- Q1 → O2 (mittauspisteet)
- Q2 → O3 (datan keruu ja yhdistäminen)
- Q3 → O3–O4 (mittarit ja analytiikka)
- Q4 → O4 (AI/ML-käyttö)
- Q5 → O5 (ohjausstrategiat)
- Q6 → O6 (jatkuva optimointi ja kypsyystaso)

---

## Vastausasteikko pisteytettäville kysymyksille

Jos ei erikseen mainita toisin, käytä asteikkoa:

- **0** = Ei lainkaan / ei käytössä  
- **1** = Osittain / rajallisesti / kokeiluluonteisesti  
- **2** = Kattavasti / vakiintunut käytäntö

---

## Q0 – Taustatiedot (ei pisteytetä)

**Q0.1 Konesalin tyyppi**  
(Valitse yksi tai useampi)

- [ ] Oma konesali (on-premises)
- [ ] Colocation-konesali
- [ ] Pilvipalveluoperaattori (DC omassa hallinnassa)
- [ ] Muu, mikä: ______________________

**Q0.2 Pääsijainti ja jäähdytysratkaisu**

- Sijainti (kaupunki/alue): ______________________  
- Jäähdytyksen päätyyppi:
  - [ ] Ilmajäähdytys
  - [ ] Neste-/vesijäähdytys
  - [ ] Hybridiratkaisu
  - [ ] Muu: ______________________

**Q0.3 Energialähde**

- [ ] Pääosin verkosta ostettava sähkö
- [ ] Omavarainen / osittain omavarainen tuotanto (esim. aurinko, tuuli)
- [ ] Pitkäaikaiset vihreän energian sopimukset (PPA tms.)
- Lisätietoja: ______________________

**Q0.4 Onko datakeskukselle asetettu konkreettisia energiatehokkuus- tai CO₂-tavoitteita?**

- [ ] Ei  
- [ ] Kyllä, yleisellä tasolla  
- [ ] Kyllä, mitattavina tavoitteina (esim. PUE/CO₂-tasot)

Jos vastasit **kyllä**, kuvaile lyhyesti:  
_Tavoitteet:_ _____________________________________________

> **Jos tavoitteet ja roolit ovat epäselviä, katso Optimointioppaan lukua O1.**

---

## Q1 – Mittauspisteet ja mitattavat suureet (O2)

**Asteikko: 0 = ei mitata, 1 = jonkin verran, 2 = kattavasti**

### Q1.1 Sähkönsyöttö (E_infra)

**Q1.1.1 Mitataanko kokonaisenergiankulutusta pääkeskustasolla?**  
(0–2): __

**Q1.1.2 Mitataanko UPS-järjestelmien energiankulutusta?**  
(0–2): __

**Q1.1.3 Mitataanko PDU- / räkkitasolla IT-laitteiden kulutusta?**  
(0–2): __

---

### Q1.2 Jäähdytys

**Q1.2.1 Mitataanko jäähdytysjärjestelmän kokonaisenergiankulutusta?**  
(0–2): __

**Q1.2.2 Mitataanko lämpötiloja konesalissa (esim. kuuma/kylmä käytävä, tulo-/poistoilma)?**  
(0–2): __

**Q1.2.3 Mitataanko ilmavirtoja, pumppujen tai puhaltimien tehoa?**  
(0–2): __

---

### Q1.3 IT-kuorma (E_data)

**Q1.3.1 Mitataanko palvelinkuormaa (CPU, muisti) klusteri- tai palvelinkohtaisesti?**  
(0–2): __

**Q1.3.2 Mitataanko IT-laitteiden virrankulutusta (esim. per räkki/klusteri)?**  
(0–2): __

---

### Q1.4 Tallennus ja verkko

**Q1.4.1 Mitataanko tallennusjärjestelmien (storage) energiankulutusta?**  
(0–2): __

**Q1.4.2 Mitataanko verkkolaitteiden (kytkimet, reitittimet jne.) energiankulutusta?**  
(0–2): __

---

### Q1.5 Ympäristö ja ulkoiset suureet

**Q1.5.1 Mitataanko tai haetaanko ulkolämpötila automaattisesti ohjauksen tueksi?**  
(0–2): __

**Q1.5.2 Tunnetaaneko käytetyn sähkön CO₂-intensiteetti (gCO₂/kWh) ja käytetäänkö sitä laskennassa?**  
(0–2): __

**Q1.5.3 Mitataanko hukkalämmön määrä ja lämpötilataso (jos lämpöä hyödynnetään)?**  
(0–2): __

> **Jos useimmiten vastasit 0–1, kehityskohteet löytyvät luvusta O2.**

---

## Q2 – Datan keruu ja yhdistäminen (O3)

**Asteikko ellei toisin mainita: 0–2**

**Q2.1 Mitä valvonta- ja hallintajärjestelmiä käytätte?**  
(voi valita useita, tätä ei pisteytetä)

- [ ] BMS (Building Management System)  
- [ ] DCIM (Data Center Infrastructure Management)  
- [ ] Pilvipohjaiset valvontatyökalut  
- [ ] Muita (Grafana, Prometheus, Zabbix tms.): ___________________  

**Q2.2 Kuinka usein mittausdataa kerätään ja tallennetaan?**

- [ ] Vain manuaalisesti / satunnaisesti (0)  
- [ ] Tunti- tai päivätasolla (1)  
- [ ] Minuutti- tai reaaliaikatasolla (2)  
Pisteet: __

**Q2.3 Kuinka pitkältä ajalta historiadataa säilytetään?**

- [ ] Alle 3 kuukautta (0)  
- [ ] 3–12 kuukautta (1)  
- [ ] Yli 12 kuukautta (2)  
Pisteet: __

**Q2.4 Yhdistetäänkö infra-, IT- ja jäähdytysdata samaan analytiikkakerrokseen (esim. samaan tietokantaan / raportointiin)?**  
(0–2): __

**Q2.5 Onko olemassa keskitettyä “totuuden lähdettä”, johon energiankulutus- ja mittaridata (kuten PUE) kootaan?**  
(0–2): __

> **Jos data on hajallaan tai historia on lyhyt, katso luku O3.**

---

## Q3 – Mittarit ja perusanalytiikka (O3–O4)

**Q3.1 Lasketaanko PUE-lukua?**

- [ ] Ei koskaan (0)  
- [ ] Satunnaisesti / projekteissa (1)  
- [ ] Säännöllisesti (esim. kuukausi-/kvartaali- tai viikkotasolla) (2)  
Pisteet: __

**Q3.2 Lasketaanko WUE- tai muita vedenkäyttöön liittyviä mittareita?**  
(0–2): __

**Q3.3 Lasketaanko CUE:ta tai muita hiilijalanjälkeen liittyviä tunnuslukuja (gCO₂/kWh tms.)?**  
(0–2): __

**Q3.4 Onko käytössä raportteja tai näkymiä, jotka näyttävät:**

- Kokonaisenergiankulutuksen ja sen jakautumisen IT vs. muu infra  
- Jäähdytyksen osuuden kokonaisenergiankulutuksesta  
- Hukkalämmön määrän ja hyötykäytön

Arvio:  
- 0 = ei lainkaan  
- 1 = joitakin raportteja, mutta eivät säännöllisiä  
- 2 = vakiintunut raportointi / dashboardit  
Pisteet: __

**Q3.5 Seurataanko toimenpiteiden (esim. lämpötilan nosto, laitepäivitys) vaikutusta ennen–jälkeen -vertailulla?**  
(0–2): __

**Q3.6 Onko johdolla selkeä näkyvyys energiatehokkuuteen ja CO₂-lukuihin (esim. KPI-näkymä)?**  
(0–2): __

> **Jos mittarit ja raportointi ovat satunnaisia, painopiste luvussa O3 (ja O4 kun mittareita halutaan käyttää mallien tavoitteina).**

---

## Q4 – AI/ML-käyttö ja syväoppimisen käyttötapaukset (O4)

**Q4.1 Käytetäänkö analytiikkaa tai AI/ML-malleja seuraaviin:**  
(merkitse per kohta: 0 = ei, 1 = pilotti/koe, 2 = tuotantokäytössä)

- Q4.1.1 Energiankulutuksen ja PUE:n ennustaminen: __  
- Q4.1.2 Jäähdytysasetusten ja lämpötilojen optimointi: __  
- Q4.1.3 Palvelinkuorman ja kapasiteetin ennustaminen: __  
- Q4.1.4 Hukkalämmön hyödyntämisen optimointi: __  
- Q4.1.5 Poikkeamien ja anomalioiden tunnistaminen (esim. kulutuspiikit): __  

**Q4.2 Miten mallit ovat käytössä? (valitse sopivin)**

- [ ] Vain analyysin tukena (raportit, simulaatiot) (1)  
- [ ] Antavat ehdotuksia, joita ihminen arvioi ennen toteutusta (2)  
- [ ] Säätävät automaattisesti joitakin asetuksia (esim. lämpötila, kuorman siirto) (2)  
- [ ] Ei käytössä (0)  

Pisteet: __

**Q4.3 Kuinka hyvin mittarit (PUE, CO₂, lämpötilat, SLA) on kytketty mallien tavoitteiksi tai rajoiksi?**  
(0–2): __

> **Jos AI/ML on vasta ajatuksen tasolla, lue erityisesti luku O4.**

---

## Q5 – Ohjausstrategiat (O5)

**Q5.1 Miten konesalin ohjaus tällä hetkellä pääasiassa toteutuu?**

- [ ] Kiinteät asetukset, harvoin muutoksia (0)  
- [ ] Manuaaliset säädöt henkilökunnan harkinnan mukaan (1)  
- [ ] Osittain automaattinen ohjaus mittarien perusteella (2)  
Pisteet: __

**Q5.2 Onko määritelty ohjausarkkitehtuuri (kuka/mikä järjestelmä säätää mitäkin)?**  
(0–2): __

**Q5.3 Onko määritelty selkeät raja-arvot (esim. lämpötila- ja PUE-tavoitteet), joiden puitteissa ohjaus voi toimia?**  
(0–2): __

**Q5.4 Onko olemassa fallback-strategiat: mitä tehdään, jos malli tai automaatio toimii odottamattomasti?**  
(0–2): __

**Q5.5 Onko määritelty prosessi, miten uudet ohjauslogiikat (esim. AI/ML) otetaan käyttöön vaiheittain ja testataan turvallisesti?**  
(0–2): __

> **Jos ohjaus perustuu pääosin käsin tehtyihin ratkaisuihin, kehityskohteet löytyvät luvusta O5.**

---

## Q6 – Jatkuva optimointi, prosessit ja kypsyystaso (O6)

**Q6.1 Onko organisaatiossa nimetty vastuuhenkilöt tai -roolit energiatehokkuuden ja CO₂-optimoinnin seurantaan?**  
(0–2): __

**Q6.2 Onko käytössä säännöllinen katselmus tai palaveri, jossa energiankulutusta, PUE/WUE/CUE-lukuja ja optimointitoimia käydään läpi?**  
(0–2): __

**Q6.3 Onko määritelty vuosikello tai kehityssuunnitelma (mitä mitataan ja kehitetään minäkin ajankohtana)?**  
(0–2): __

**Q6.4 Onko suunnitelma tai käytäntö toistaa tämä optimointikartoitus (Q) esimerkiksi vuosittain?**  
(0–2): __

**Q6.5 Miten arvioitte omaa kypsyystasoa? (valitkaa lähinnä oleva)**

- [ ] Taso 1: Mittaus ja optimointi vasta alussa (0)  
- [ ] Taso 2: Mittaus ja analytiikka kohtuullisella tasolla, yksittäisiä optimointitoimia (1)  
- [ ] Taso 3: Mittarit, analytiikka ja optimointimallit osa normaalia operointia (2)  
Pisteet: __

> **Jos jatkuva optimointi ei ole vielä prosessi, vaan yksittäisiä projekteja, lue luku O6.**
