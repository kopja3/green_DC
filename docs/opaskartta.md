# Vihreä datakeskus – oppaiden ristiinviittausmuistio

Tällä muistilapulla pidetään kirjaa siitä,
mitkä Perusoppaan ja Optimointioppaan luvut
syventävät Itseopiskelijan oppaan moduuleja.

Optimointiopas on fokusoitu **käytönaikaiseen optimointiin**, jossa
datakeskuksesta kerätään mittausdataa, ja data-analytiikkaa sekä
syväoppimista hyödynnetään mm. sähkönkulutuksen ja CO₂-päästöjen
pienentämiseen, palvelinkuorman ja jäähdytyksen yhteentoimivuuden
optimointiin, hukkalämmön älykkääseen hyödyntämiseen sekä käytön ja
operoinnin jatkuvaan parantamiseen.

---

## Mitä teen seuraavaksi? (työsuunnitelma)

### Vaihe 1 – Perusoppaan (P) jäsentely nykyisestä tekstistä

- [ ] Avaa nykyinen Perusopas ja lisää siihen nämä pääluvut otsikoiksi: **P1–P7** (ks. alla oleva sisällysluettelo).
- [ ] Jaa olemassa oleva sisältö näiden otsikoiden alle:
  - P1: yleinen johdanto ja vihreän konesalin idea
  - P2: tehtävä + sijainti (tarve, sijaintipäätös, liitynnät)
  - P3: vihreän datakeskuksen elementit
  - P4: elinkaaren vaiheet
  - P5: toiminta (sähkö → palvelin → lämpö)
  - P6: energian kulutus ja hukkalämpö
  - P7: EN 50600-4 ja muut mittarit (PUE, CUE, WUE, REF/ERF, CER…)
- [ ] Tarkista, että P7:ssä on selkeä ja yhtenäinen mittariosio (voit käyttää nykyistä PUE/REF/ERF/WUE-tekstiä lähes sellaisenaan).
- [ ] Kirjoita jokaisen luvun alkuun lyhyt lause tyyliin:
  - *"Tämä luku (P3) syventää Itseopiskelijan oppaan moduuleja M2 ja M5."*

### Vaihe 2 – Optimointioppaan (O) käynnistäminen

- [ ] Kirjoita **O1 – Johdanto data- ja tekoälyohjattuun optimointiin** (1–2 sivua):
  - mitä käytönaikainen optimointi tarkoittaa
  - tavoitteet: CO₂, kWh, kustannus, palvelun laatu, riskit
  - miten O-opas liittyy Itseopiskelijan oppaan moduuleihin (M1–M6) ja Perusoppaaseen (P1–P7)
- [ ] Luonnostele **O2 – Datakeskus tekoälyn näkökulmasta: mittauspisteet ja mitattavat suureet**:
  - tee lista mittauspisteistä: sähkö, jäähdytys, IT-kuorma, vesi, hukkalämpö, ulkoiset signaalit (sää, hinnat…)
  - kuvaa lyhyesti datatyypit (aikasarjat, tapahtumat) ja datan laatu / mittaustiheys
- [ ] Lisää O1:n ja O2:n alkuun muistilauseet:
  - O1: *"Tämä luku tukee kaikkia moduuleja M1–M6."*
  - O2: *"Tämä luku syventää erityisesti moduuleja M2, M4, M5 ja M6."*

### Vaihe 3 – Tarkista ristiinviittaukset

- [ ] Tämä `opas.md` toimii “master-karttana”. Kun muokkaat tekstiä, merkitse marginaaliin / kommentteihin:
  - **P-koodi** (mihin Perusoppaan lukuun kappale kuuluu)
  - **O-koodi** (jos kappale liittyy optimointiin)
- [ ] Kun P1–P7 ja O1–O2 ovat luonnosvaiheessa valmiit, palaa tähän tiedostoon ja tarkista, että
  - Taulukko 1 ja tarkemmat kartat vastaavat sitä, mitä olet oikeasti kirjoittanut.

---

## Lyhyt muistio koodeista

- **M1–M6** = Itseopiskelijan oppaan moduulit  
- **P1–P7** = Perusoppaan luvut  
- **O1–O6** = Optimointioppaan luvut  

Esim. merkintä **M2 → P3, O2, O4** tarkoittaa:
Moduuli 2 syvenee Perusoppaan luvussa 3 ja Optimointioppaan luvuissa 2 ja 4.

---

## Perusopas – luonnos sisällysluetteloksi

1. **P1 – Johdanto vihreään datakeskukseen**  
2. **P2 – Miksi datakeskus rakennetaan ja miten sijainti valitaan**  
3. **P3 – Vihreän datakeskuksen elementit ja periaatteet**  
4. **P4 – Datakeskuksen elinkaaren vaiheet**  
5. **P5 – Datakeskuksen toiminta: sähköstä palveluksi ja takaisin lämmöksi**  
6. **P6 – Energian kulutus ja hukkalämmön hyödyntäminen**  
7. **P7 – EN 50600-4 -mittarit ja muut keskeiset tunnusluvut**

## Optimointiopas – luonnos sisällysluetteloksi

1. **O1 – Johdanto data- ja tekoälyohjattuun optimointiin**  
2. **O2 – Datakeskus tekoälyn näkökulmasta: mittauspisteet ja mitattavat suureet**  
3. **O3 – Datan keruu, yhdistäminen ja perusanalytiikka**  
4. **O4 – Syväoppimisen käyttötapaukset: kulutus, jäähdytys, kuorma ja hukkalämpö**  
5. **O5 – Ohjausstrategiat: miten mallit kytketään konesalin ohjaukseen**  
6. **O6 – Jatkuva käytönaikainen optimointi, operointi ja riskienhallinta**

> Huom: Optimointioppaan luku **O1** tukee kaikkia moduuleja, joten se
> mainitaan useilla riveillä.

---

## Taulukko 1 – Moduulit ja niitä syventävät luvut

| Moduuli (Itseopiskelijan opas) | Perusopas – luku/sivu(t), joka syventää taustaa | Optimointiopas – luku/sivu(t), joka syventää optimointia | Huomiot / mitä tässä kannattaa syventää |
|--------------------------------|-------------------------------------------------|----------------------------------------------------------|-----------------------------------------|
| **M1 – Datakeskuksen rakentamisen syyt ja sijaintipäätösten perusteet** | P1 (Johdanto vihreään datakeskukseen); P2 (Miksi datakeskus rakennetaan ja miten sijainti valitaan) | O1 (Johdanto data- ja tekoälyohjattuun optimointiin – tavoitteet ja periaatteet) | syyt rakentamiselle, sijaintikriteerit, peruskäsitteet, miksi optimointia tarvitaan |
| **M2 – Vihreän datakeskuksen elementit ja periaatteet** | P3 (Vihreän datakeskuksen elementit ja periaatteet) | O1 (optimoinnin yleinen tavoite); O2 (mittauspisteet); O4 (syväoppimisen käyttötapaukset: jäähdytys, kuorma, hukkalämpö, vesi, hiilineutraalius) | energianlähde, energiatehokkuus, hukkalämpö, vesi, hiilineutraalius, kiertotalous, sertifioinnit |
| **M3 – Datakeskuksen elinkaaren vaiheet** | P4 (Datakeskuksen elinkaaren vaiheet) | O1 (optimointi osana elinkaarta); O6 (jatkuva käytönaikainen optimointi, operointi ja riskienhallinta) | suunnittelu–rakentaminen–käyttö–purku; mihin vaiheeseen AI-pohjainen optimointi erityisesti kytkeytyy (käyttö ja operointi) |
| **M4 – Datakeskuksen toiminta vaiheittain** | P5 (Datakeskuksen toiminta: sähköstä palveluksi ja takaisin lämmöksi) | O2 (mittauspisteet sähkönsyötöstä, jäähdytyksestä ja palvelinkuormasta); O4 (syväoppimisen käyttötapaukset kuorman ja jäähdytyksen yhteispelistä); O5 (ohjausstrategiat – miten mallit vaikuttavat asetuksiin) | sähkö → palvelin → lämpö, tekninen perusta ja optimointikohdat (jäähdytys, kuorma, hukkalämpö) |
| **M5 – Energian kulutus ja uudelleenkäyttö** | P6 (Energian kulutus ja hukkalämmön hyödyntäminen) | O1 (tavoitteena CO₂- ja energiankulutuksen pienentäminen); O3 (datan keruu ja perusanalytiikka: kulutus, PUE, hukkalämpö); O4 (syväoppimisen käyttötapaukset: kulutuksen ennustaminen, PUE-optimointi, hukkalämmön ohjaus); O5 (ohjausstrategiat) | PUE, kokonaiskulutus, kulutuksen vähentäminen, hukkalämmön älykäs hyödyntäminen |
| **M6 – EN 50600-4 -standardi ja mittarit** | P7 (EN 50600-4 -mittarit ja muut keskeiset tunnusluvut) | O1 (mittareiden rooli optimoinnissa); O3 (mittaridatan keruu ja yhdistäminen); O6 (jatkuva käytönaikainen optimointi – mittareihin perustuva seuranta ja päätöksenteko) | mittareiden idea (perus) ja käytännön käyttö: mihin mittareita syötetään ja miten AI hyödyntää niitä |

---

## (Valinnainen) Tarkempi kartta Moduuli 1:lle

| Moduuli 1: Datakeskuksen rakentamisen syyt ja sijaintipäätösten perusteet | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|--------------------------------------------|------------------------|----------------------------|--------|
| Tarve ja rooli (miksi datakeskus rakennetaan) | P1; P2, osio ”Miksi datakeskus rakennetaan” | O1 (mitä optimoinnilla tavoitellaan) | liiketoiminta-, palvelu- ja regulaatiotarpeet, miksi oma datakeskus / konesali on olemassa; pohjustaa, miksi optimointi on järkevää |
| Oma datakeskus vs. pilvipalvelut (ratkaisuvaihtoehdot) | P2, osio ”Oma datakeskus, kolmannen osapuolen konesali vai pilvipalvelut” | O1 (milloin käytönaikainen optimointi on omissa käsissä); tarvittaessa O2 (mittauspisteet eri ratkaisumalleissa) | missä tilanteissa datan ja ohjauksen omistajuus mahdollistaa AI-pohjaisen optimoinnin (oma / colocation vs. pilvi) |
| Sijainnin tekniset tekijät (sähkö, verkko, ilmasto) | P2, osio ”Sijainnin tekniset tekijät” | O2 (mittauspisteet sähkönsyötölle, verkolle, ulkolämpötilalle); O3 (datan keruu ja yhdistäminen) | sähkön saatavuus ja hinta, verkon latenssi ja kapasiteetti, ilmasto ja jäähdytystarve – nämä vaikuttavat siihen, millaista dataa myöhemmin saadaan malleille |
| Sijainnin ympäristö- ja energiatehokkuustekijät | P2, osio ”Ympäristö ja energiatehokkuus sijaintipäätöksessä” | O1 (CO₂- ja energiatavoitteet); O2 (mittauspisteet uusiutuvan energian osuudelle ja hukkalämmölle); O4 (case-tyyppiset käyttötapaukset energian ja päästöjen optimoinnista) | uusiutuvan energian osuus, hukkalämmön hyödyntämismahdollisuudet, veden saatavuus – sijainti määrittelee optimoinnin potentiaalin |
| Riskit ja resilienssi (turvallisuus, vakaus, häiriöt) | P2, osio ”Riskit ja resilienssi” | O6 (jatkuva käytönaikainen optimointi, operointi ja riskienhallinta) | fyysiset riskit (tulva, sähkökatkot, poliittinen riski) ja niiden merkitys myös AI-pohjaisen ohjauksen kannalta; varmistetaan, ettei optimointi heikennä resilienssiä |
| Tavoitetason määrittely (vihreys, PUE/CO₂-tavoitteet, mittarit) | P1; P7 (EN 50600-4 -mittarit ja muut tunnusluvut) | O1 (tavoitteiden asettaminen); O3 (datan keruu ja perusanalytiikka tavoitteiden seurantaan); O6 (jatkuva optimointi ja mittaripohjainen päätöksenteko) | tässä päätetään, millaisia mittareita (PUE, CO₂, WUE jne.) seurataan ja mihin syväoppimismalleja myöhemmin käytetään; luo raamit optimointityölle |

---

## (Valinnainen) Tarkempi kartta Moduuli 2:lle

| Moduuli 2: Vihreän datakeskuksen elementit | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|-------------------------------------------|------------------------|----------------------------|--------|
| Energianlähde                            | P3, osio ”Energianlähde” | O2: mittauspisteet energianlähteeseen liittyen (esim. uusiutuvan energian osuus, sopimustiedot); O4: case energianlähteen ja CO₂-intensiteetin optimoinnista | energialähteen valinta, uusiutuvan osuuden seuranta ja vaikutus CO₂:een |
| Energiatehokkuus                         | P3, osio ”Energiatehokkuus” | O2: IT- ja jäähdytyskuorman mittarit; O4: case jäähdytyksen ja palvelinkuorman optimoinnista; O5: ohjausstrategiat (asetukset, ohjauslogiikka) | lämpötilat, ilmavirrat, kuormanjako, konsolidointi, vaikutus PUE:hen |
| Hukkalämmön hyödyntäminen                | P3, osio ”Hukkalämmön hyödyntäminen” | O2: lämmön mittarit (teho, lämpötilatasot); O4: case hukkalämmön ohjauksesta (milloin ja minne lämpö ohjataan); O5: ohjausstrategiat | lämpöteho, lämpötilatasot, kytkentävaihtoehdot, kysynnän mukaan ohjaaminen |
| Vedenkulutus                             | P3, osio ”Vedenkulutus” | O2: vesijäähdytyksen ja vedenkulutuksen mittarit; O4: case vedenkulutuksen vähentämisestä ilman riskien kasvua | WUE, jäähdytystapojen vertailu, vedenkulutuksen ja energiankulutuksen kompromissi |
| Hiilineutraalius ja raportointi          | P3, osio ”Hiilineutraalius ja raportointi” | O3: datan keruu päästölaskentaa varten (CO₂-intensiteetti, kulutus); O4: case hiilineutraaliustavoitteiden seuraamisesta mallien avulla; O6: mittareiden ja tavoitteiden jatkuva seuranta | Scope 1–3 perusajatus, datalähteet, raportointiketju ja AI:n rooli trendien tunnistamisessa |
| Kiertotalous ja materiaalien hallinta    | P3, osio ”Kiertotalous ja materiaalien hallinta” | O6: jatkuva optimointi ja laitekannan elinkaaren seuranta (esim. käyttöaste, ikä, energiatehokkuus) | laitteiden elinkaari, päivitysrytmi, poisto- ja kierrätysdata, energiatehokkuus vs. uusiminen |
| Sertifioinnit ja standardit              | P3, osio ”Sertifioinnit ja standardit” | O6: jatkuva optimointi ja vaatimustenmukaisuus (mitä dataa AI ja mittarit voivat tuottaa sertifioinnin tueksi) | EN 50600, ISO 50001 jne., miten mittarointi ja AI helpottavat auditointeja |

---

## (Valinnainen) Tarkempi kartta Moduuli 3:lle

| Moduuli 3: Datakeskuksen elinkaaren vaiheet | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|--------------------------------------------|------------------------|----------------------------|--------|
| Esiselvitys (tarve, vaihtoehdot, vihreän tason tavoitteet) | P4, osio ”Elinkaaren vaiheet – esiselvitys” | O1: johdanto optimointitavoitteisiin; O2: mittauspisteiden ja datatarpeen suunnittelu | määritellään energiatehokkuus-, CO₂- ja hukkalämpötavoitteet jo ennen suunnittelua |
| Suunnittelu (sijainti, kapasiteetti, perusratkaisut) | P2 (sijaintipäätökset); P4, osio ”Suunnitteluvaihe” | O2: mihin kaikkiin järjestelmiin asennetaan mittarit; O3: datan keruun arkkitehtuurin suunnittelu | suunnittelussa päätetään, mitä voidaan myöhemmin mitata ja optimoida (jäähdytys, sähkö, kuorma, hukkalämpö) |
| Rakentaminen (toteutus periaatteiden pohjalta) | P4, osio ”Rakentaminen” | O3: datan keruun toteutus (mittareiden asennus, liitynnät järjestelmiin) | varmistetaan, että mittarit, lokit ja rajapinnat tulevat fyysisesti ja loogisesti paikoilleen |
| Käyttöönotto (testaus, ensimmäiset mittaukset) | P4, osio ”Käyttöönotto” | O3: ensimmäinen datan keruu ja perusanalytiikka; O4: ensimmäiset mallit (esim. perusennuste kulutukselle) | baseline-mittaukset, vertailutavoitteiden asettaminen, ensimmäiset AI/ML-kokeilut turvallisesti |
| Käyttö ja operointi (normaali arki konesalissa) | P4, osio ”Käyttö ja operointi” | O4: syväoppimisen käyttötapaukset (kulutus, jäähdytys, kuorma, hukkalämpö); O5: ohjausstrategiat; O6: jatkuva optimointi ja riskienhallinta | jatkuva mittaus, AI-mallit käytössä ohjauksen tukena, PUE/CO₂-seuranta, häiriöiden tunnistus |
| Modernisointi ja kapasiteetin laajennus | P4, osio ”Modernisointi ja laajennukset” | O3: analytiikka päätöksenteon tukena (milloin päivitetään laitteita); O6: pitkän aikavälin trendit ja optimoinnin vaikutusten seuranta | päätetään, mitä kannattaa uusia energiatehokkuuden ja kapasiteetin kannalta; hyödynnetään historiadataa ja malleja |
| Purku ja elinkaaren loppu (kiertotalous) | P4, osio ”Purku ja elinkaaren loppu”; P3 (kiertotalous) | O6: elinkaaritiedon hyödyntäminen (ikä, käyttöaste, energiatehokkuus) tulevien ratkaisujen suunnittelussa | miten opitaan vanhasta datakeskuksesta: mikä toimi, mikä ei, kiertotalous ja opit seuraavaan hankkeeseen |

---

## (Valinnainen) Tarkempi kartta Moduuli 4:lle

| Moduuli 4: Datakeskuksen toiminta vaiheittain | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|----------------------------------------------|------------------------|----------------------------|--------|
| Sähkönsyöttöketju (verkosta konesaliin ja kaapeille) | P5, osio ”Sähkönsyöttö ja virranjakelu” | O2: mittauspisteet sähkönsyötössä (kokonaiskulutus, UPS, PDU); O3: kulutus- ja häviödatasta perusanalytiikka; O4: case sähkönsyötön hyötysuhteen ja kuormituksen optimoinnista | muuntajat, UPS, PDU:t, niiden häviöt ja kuormitus; missä syntyy sähköhävikkiä ja miten se tunnistetaan datasta |
| Jäähdytysjärjestelmät (ilma, neste, free cooling) | P5, osio ”Jäähdytys ja lämpötilanhallinta” | O2: mittauspisteet jäähdytyksessä (lämpötilat, ilmavirrat, pumput, puhaltimet); O3: jäähdytyksen energiadatan analysointi; O4: case jäähdytyksen ja palvelinkuorman yhteisoptimoinnista; O5: ohjausstrategiat (asetusten säätö) | jäähdytyksen osuus kokonaiskulutuksesta, lämpötila-asetukset, ilmavirrat, free coolingin käyttö; AI/ML voi hakea asetuksia, jotka minimoivat kulutuksen lämpörajojen sisällä |
| Palvelinkuorma ja palvelimet (laskenta, virtualisointi, tallennus) | P5, osio ”Palvelimet ja tallennus” | O2: mittauspisteet palvelinkuormalle (CPU, muisti, virrankulutus); O4: case palvelinkuorman sijoittelusta ja konsolidoinnista; O5: ohjausstrategiat (kuorman siirrot, sammuttaminen) | kuormanjako, idle-kapasiteetti, konsolidointi; syväoppimista voidaan käyttää ennustamaan kuormaa ja ehdottamaan energiatehokkaampaa sijoittelua |
| Verkkoliikenne ja reititys (pyyntö internetistä palvelimelle ja takaisin) | P5, osio ”Verkko ja yhteydet” | O2: verkkolaitteiden ja liikenteen mittauspisteet (kuorma, virrankulutus); O3: verkkodatan analytiikka; tarvittaessa O4: case verkon ja palvelinkuorman yhteisvaikutuksesta | verkon kuormitus vaikuttaa osaltaan energiankulutukseen ja viiveisiin; datan perusteella voidaan tunnistaa turhat pullonkaulat ja ylikapasiteetti |
| Hukkalämpö polun lopussa (lämpö takaisin ympäristöön tai hyödynnettäväksi) | P5, osio ”Lämmöstä hukkalämmöksi ja hyötykäyttöön”; P6: ”Energian kulutus ja hukkalämmön hyödyntäminen” | O2: mittauspisteet lämpöteholle ja lämpötilatasoille; O4: case hukkalämmön ohjauksesta (milloin ja minne lämpö ohjataan); O5: ohjausstrategiat (lämmönsyötön ohjaus kysynnän mukaan) | missä kohtaa ketjua lämpö kerätään talteen, kuinka paljon ja millä lämpötilalla; AI/ML voi optimoida hukkalämmön ohjausta kysynnän ja ulkoisten olosuhteiden perusteella |
| Mittaustiedon kulku ja integraatiot (BMS, DCIM, mittarit) | P5, mahdollinen osio ”Valvonta ja hallintajärjestelmät” (tai viittaus luvun yleisesittelyyn) | O2: mittauspisteiden kartoitus ja järjestelmäkohtainen data; O3: datan yhdistäminen yhteiseen analytiikkakerrokseen; O6: jatkuva optimointi ja operointi | missä järjestelmissä data syntyy ja miten se saadaan AI-malleille; olennaista koko optimointioppaan kannalta |
| Palautesilmukat: miten ohjaus vaikuttaa energiankulutukseen | P5 (viittaus ketjun kokonaiskuvaan) | O4: syväoppimisen käyttötapaukset (esim. asetusten vaikutus kulutukseen); O5: ohjausstrategiat; O6: riskienhallinta ja valvonta | osoittaa, että kyse ei ole vain seurannasta, vaan mallien tuottamasta palautesilmukasta: mallit tuottavat ehdotuksia ja ohjaus muuttaa järjestelmän käyttäytymistä |

---

## (Valinnainen) Tarkempi kartta Moduuli 5:lle

| Moduuli 5: Energian kulutus ja uudelleenkäyttö | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|-----------------------------------------------|------------------------|----------------------------|--------|
| Kokonaisenergiankulutus ja sen jakautuminen (IT vs. muu infrastruktuuri) | P6, osio ”Energian kulutus datakeskuksessa” | O1: johdanto (tavoitteena kulutuksen ja CO₂:n pienentäminen); O3: datan keruu ja perusanalytiikka (kokonaiskulutus, IT vs. ei-IT) | peruskuva: mistä kWh:t syntyvät; optimointioppaan puolella data pilkotaan analysoitavaan muotoon |
| PUE ja muut energiatehokkuuden mittarit | P6, osio ”PUE ja muut tehokkuusluvut”; P7: EN 50600-4 -mittarit | O3: PUE- ja muiden mittarien laskenta datasta; O4: case PUE:n ennustamisesta ja optimoinnista; O5: ohjausstrategiat (miten mittareita käytetään säätöpäätöksissä) | PUE selitetään perusoppaassa intuitiivisesti, optimointioppaassa siitä tulee mallien keskeinen tavoitemuuttuja |
| IT-kuorman vaikutus energiankulutukseen | P6 (viittaus IT-kuorman osuuteen kokonaiskulutuksesta); P5 (palvelin-osio) | O2: mittauspisteet palvelinkuormalle (CPU, muisti, virta); O4: case IT-kuorman ja energiankulutuksen mallintamisesta; O5: ohjausstrategiat (kuorman siirrot, konsolidointi, sammuttaminen) | miten liikenne ja kuorma näkyvät kWh-luvuissa; AI voi oppia suhteita kuorman ja kulutuksen välillä |
| Jäähdytyksen energiankulutus ja sen suhteellinen osuus | P6, osio ”Jäähdytyksen osuus energiankulutuksesta” | O2: mittauspisteet jäähdytyksessä (tehot, lämpötilat, ilmavirrat); O3: jäähdytysjärjestelmän energiadatan analytiikka; O4: case jäähdytyksen optimoinnista IT-kuorman kanssa; O5: ohjausstrategiat (setpointit, free cooling, pumppujen/tuulettimien ohjaus) | usein suurin yksittäinen ei-IT-kuluerä; syväoppiminen voi etsiä energiatehokkaimmat lämpötila- ja virtausasetukset turvallisesti |
| Hukkalämmön synty ja potentiaali | P6, osio ”Hukkalämpö ja sen potentiaali” | O2: mittauspisteet lämpöteholle ja lämpötilatasoille; O3: lämmön energiataseen analytiikka; O4: case hukkalämmön ohjauksesta (milloin lämpö hyödynnetään ja miten se vaikuttaa kokonaiskulutukseen ja CO₂:een) | perusoppaassa selitetään, mitä hukkalämmöllä tarkoitetaan; optimointioppassa mallit auttavat ohjaamaan lämpöä sinne, missä se tuottaa eniten hyötyä |
| Hukkalämmön hyödyntäminen käytännössä (kaukolämpö tms.) | P6, konkreettiset esimerkit hukkalämmön hyödyntämisestä | O4: case hukkalämmön hyödyntämisen ohjauksesta (esim. dynaaminen ohjaus kysynnän, ulkolämpötilan ja energiahinnan mukaan); O5: ohjausstrategiat | AI/ML voi huomioida ulkoiset signaalit (lämpötilat, hinnat) ja päättää, milloin hukkalämmön hyödyntäminen on taloudellisesti ja ekologisesti optimaalisinta |
| Kulutusprofiilit ja kuormituksen ajallinen vaihtelu (päivä/viikko/vuosi) | P6, mahdollinen osio ”Kulutusprofiilit ja kuormituksen vaihtelu” | O3: aikasarja-analytiikka ja kulutusprofiilit; O4: case kulutuksen ennustamisesta (ennusteet ohjaavat sekä kapasiteettia että energiankäyttöä) | syväoppiminen (esim. LSTM) voi ennustaa tulevaa kulutusta ja auttaa varautumaan sekä optimoimaan ajoitusta |
| Energiansäästötoimet ja niiden vaikutusten arviointi | P6, osio ”Energiansäästötoimet” | O3: ennen–jälkeen-analytiikka; O4: case toimenpiteiden vaikutusten mallintamisesta; O6: jatkuva optimointi (säännöllinen seuranta ja näkyvyys saavutettuihin hyötyihin) | perusopas listaa tyypillisiä toimenpiteitä; optimointiopas näyttää, miten dataa ja malleja käytetään vaikutusten todentamiseen |
| Yhteys CO₂-päästöihin ja raportointiin | P6; P7 (EN 50600-4 -mittarit ja CO₂-sidonnaiset tunnusluvut) | O1: johdanto (CO₂ vähentäminen keskeinen tavoite); O3: energiankulutuksen ja päästöintensiteetin yhdistäminen; O4: case CO₂-optimoinnista; O6: jatkuva mittaripohjainen seuranta | energian käytön ja päästöjen yhteys tehdään näkyväksi; AI voi auttaa tunnistamaan, mitkä toimet vähentävät CO₂:ta eniten |

---

## (Valinnainen) Tarkempi kartta Moduuli 6:lle

| Moduuli 6: EN 50600-4 -standardi ja mittarit | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|---------------------------------------------|------------------------|----------------------------|--------|
| EN 50600-4 -standardin rooli ja perusidea | P7, osio ”EN 50600-4 ja sen tarkoitus” | O1: johdanto (mittareiden rooli optimoinnin tavoitteiden määrittelyssä); O6: jatkuva optimointi ja mittaripohjainen seuranta | mitä standardi tekee, miksi se on olemassa, miten se liittyy vihreään konesaliin ja raportointiin |
| PUE (Power Usage Effectiveness) – peruskäsite | P7, osio ”PUE – energiatehokkuuden perusmittari” | O3: PUE:n laskenta datasta; O4: case PUE:n ennustamisesta ja optimoinnista; O5: ohjausstrategiat (mittari ohjauksen tavoitteena) | perusoppaassa selitetään intuitiivisesti, optimointioppaassa PUE toimii mallien tavoitteena ja vertailulukuna |
| CUE (Carbon Usage Effectiveness) ja CO₂-intensiteetti | P7, osio ”CUE ja hiili-intensiteetti” | O3: energiankulutuksen ja päästöintensiteetin yhdistäminen; O4: case CO₂-optimoivasta ohjauksesta; O6: CO₂-trendien seuranta | yhdistää energiankulutuksen ja päästökerroin-tiedon; AI/ML voi optimoida kohti matalampaa CUE:ta |
| WUE (Water Usage Effectiveness) – vedenkäytön mittari | P7, osio ”WUE ja vedenkulutus”; linkittyy P3:n vedenkulutuskohtaan | O2: mittauspisteet vesijäähdytykselle ja vedenkulutukselle; O3: WUE-laskenta ja trendit; O4: case vedenkulutuksen vähentämisestä | miten vedenkulutus suhteutuu IT-kuormaan; optimointioppaassa tasapaino vedenkulutuksen, energian ja riskien välillä |
| Muut EN 50600-4 -mittarit (REF/ERF, CER tms.) | P7, osio ”Muut keskeiset mittarit” | O3: mittarien laskenta ja datakenttien yhdistäminen; O4: case usean mittarin yhtäaikaisesta optimoinnista; O6: mittareiden käyttö KPI-järjestelmänä | perusoppaassa kevyet määritelmät, optimointioppaassa mittarit muodostavat “mittaripaketin”, jota mallit seuraavat |
| Mittauspisteet ja datalähteet mittareille | P7, viittaus siihen, mistä mittareiden tarvitsemat luvut periaatteessa tulevat (yhteys P5–P6 sisältöön) | O2: datakeskus tekoälyn näkökulmasta (mittauspistekartta); O3: datan yhdistäminen yhteiseen analytiikkaan | tärkeä silta: mittareita ei voi laskea ilman oikeita mittauspisteitä; optimointiopas näyttää tarkasti, mistä mikäkin tieto tulee |
| Mittaustiheys, historian pituus ja datan laatu | P7, mahdollinen osio ”Mittaroinnin perusperiaatteet” | O3: aikasarja-analytiikka, mittaustiheyden ja historiadatan merkitys; O6: jatkuvan seurannan käytännön järjestelyt | kuinka usein mittarit päivitetään, kuinka pitkää historiaa mallit tarvitsevat, mitä tehdään puuttuville arvoille |
| Mittarit raportoinnissa ja tavoitteiden asettamisessa | P7, osio ”Mittarit johtamisen ja raportoinnin välineinä” | O1: johdanto (tavoitteiden kytkentä mittareihin); O6: mittareihin perustuva päätöksenteko ja kehityspolut | perusopas: johdolle ja raporteille; optimointiopas: miten mittaritasot käännetään konkreettisiksi ohjaus- ja optimointitavoitteiksi |
| Mittarit AI-/ML-malleissa (tavoitteet, rajoitteet, palautesilmukat) | P7, lyhyt maininta mittareiden käytöstä kehittämisen tukena | O4: syväoppimisen käyttötapaukset (mittarit mallin tavoitemuuttujina); O5: ohjausstrategiat (mittarit raja-arvoina ja optimoinnin tavoitteina); O6: palautesilmukat (mittaritulokset → mallien ja asetusten säätö) | yhdistää mittarit konkreettisesti AI/ML-malleihin: mitä malli yrittää minimoida/maksimoida ja miten tuloksia käytetään ohjauksessa |
