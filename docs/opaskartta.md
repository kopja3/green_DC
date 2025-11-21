# Vihreä datakeskus – oppaiden ristiinviittausmuistio

Tällä muistilapulla pidetään kirjaa siitä,
mitkä Perusoppaan ja Optimointioppaan luvut
syventävät Itseopiskelijan oppaan moduuleja.

Optimointiopas on fokusoitu **käytön aikaiseen optimointiin**, jossa
datakeskuksesta kerätään mittausdataa, ja data-analytiikkaa sekä
syväoppimista hyödynnetään mm. sähkönkulutuksen ja CO₂-päästöjen
pienentämiseen, palvelinkuorman ja jäähdytyksen yhteentoimivuuden
optimointiin, hukkalämmön älykkääseen hyödyntämiseen sekä käytön ja
operoinnin jatkuvaan parantamiseen.

---

## Perusopas – luonnos sisällysluetteloksi

1. **Johdanto vihreään datakeskukseen**  
2. **Miksi datakeskus rakennetaan ja miten sijainti valitaan**  
3. **Vihreän datakeskuksen elementit ja periaatteet**  
4. **Datakeskuksen elinkaaren vaiheet**  
5. **Datakeskuksen toiminta: sähköstä palveluksi ja takaisin lämmöksi**  
6. **Energian kulutus ja hukkalämmön hyödyntäminen**  
7. **EN 50600-4 -mittarit ja muut keskeiset tunnusluvut**

## Optimointiopas – luonnos sisällysluetteloksi

1. **Johdanto data- ja tekoälyohjattuun optimointiin**  
2. **Datakeskus tekoälyn näkökulmasta: mittauspisteet ja mitattavat suureet**  
3. **Datan keruu, yhdistäminen ja perusanalytiikka**  
4. **Syväoppimisen käyttötapaukset: kulutus, jäähdytys, kuorma ja hukkalämpö**  
5. **Ohjausstrategiat: miten mallit kytketään konesalin ohjaukseen**  
6. **Jatkuva käytön aikainen optimointi, operointi ja riskienhallinta**

> Huom: Optimointioppaan luku 1 tukee kaikkia moduuleja, joten se
> mainitaan useilla riveillä.

---

## Taulukko 1 – Moduulit ja niitä syventävät luvut

| Moduuli (Itseopiskelijan opas) | Perusopas – luku/sivu(t), joka syventää taustaa | Optimointiopas – luku/sivu(t), joka syventää optimointia | Huomiot / mitä tässä kannattaa syventää |
|--------------------------------|-------------------------------------------------|----------------------------------------------------------|-----------------------------------------|
| **Moduuli 1 – Datakeskuksen rakentamisen syyt ja sijaintipäätösten perusteet** | Luku 1: Johdanto vihreään datakeskukseen; luku 2: Miksi datakeskus rakennetaan ja miten sijainti valitaan | Luku 1: Johdanto data- ja tekoälyohjattuun optimointiin (tavoitteet ja periaatteet) | syyt rakentamiselle, sijaintikriteerit, peruskäsitteet, miksi optimointia tarvitaan |
| **Moduuli 2 – Vihreän datakeskuksen elementit ja periaatteet** | Luku 3: Vihreän datakeskuksen elementit ja periaatteet | Luku 1: Johdanto (optimoinnin yleinen tavoite); luku 2: Datakeskus tekoälyn näkökulmasta (mittauspisteet); luku 4: Syväoppimisen käyttötapaukset (jäähdytys, kuorma, hukkalämpö, vesi, hiilineutraalius) | energianlähde, energiatehokkuus, hukkalämpö, vesi, hiilineutraalius, kiertotalous, sertifioinnit |
| **Moduuli 3 – Datakeskuksen elinkaaren vaiheet** | Luku 4: Datakeskuksen elinkaaren vaiheet | Luku 1: Johdanto (optimointi osana elinkaarta); luku 6: Jatkuva käytön aikainen optimointi, operointi ja riskienhallinta | suunnittelu–rakentaminen–käyttö–purku; mihin vaiheeseen AI-pohjainen optimointi erityisesti kytkeytyy (käyttö ja operointi) |
| **Moduuli 4 – Datakeskuksen toiminta vaiheittain** | Luku 5: Datakeskuksen toiminta: sähköstä palveluksi ja takaisin lämmöksi | Luku 2: Mittauspisteet sähkönsyötöstä, jäähdytyksestä ja palvelinkuormasta; luku 4: Syväoppimisen käyttötapaukset (kuorman ja jäähdytyksen yhteispeli); luku 5: Ohjausstrategiat (miten mallit vaikuttavat asetuksiin) | sähkö → palvelin → lämpö, tekninen perusta ja optimointikohdat (jäähdytys, kuorma, hukkalämpö) |
| **Moduuli 5 – Energian kulutus ja uudelleenkäyttö** | Luku 6: Energian kulutus ja hukkalämmön hyödyntäminen | Luku 1: Johdanto (tavoitteena CO₂- ja energiankulutuksen pienentäminen); luku 3: Datan keruu ja perusanalytiikka (kulutus, PUE, hukkalämpö); luku 4: Syväoppimisen käyttötapaukset (kulutuksen ennustaminen, PUE-optimointi, hukkalämmön ohjaus); luku 5: Ohjausstrategiat | PUE, kokonaiskulutus, kulutuksen vähentäminen, hukkalämmön älykäs hyödyntäminen |
| **Moduuli 6 – EN 50600-4 -standardi ja mittarit** | Luku 7: EN 50600-4 -mittarit ja muut keskeiset tunnusluvut | Luku 1: Johdanto (mittareiden rooli optimoinnissa); luku 3: Mittaridatan keruu ja yhdistäminen; luku 6: Jatkuva käytön aikainen optimointi (mittareihin perustuva seuranta ja päätöksenteko) | mittareiden idea (perus) ja käytännön käyttö: mihin mittareita syötetään ja miten AI hyödyntää niitä |

---

## (Valinnainen) Tarkempi kartta Moduuli 1:lle

| Moduuli 1: Datakeskuksen rakentamisen syyt ja sijaintipäätösten perusteet | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|--------------------------------------------|------------------------|----------------------------|--------|
| Tarve ja rooli (miksi datakeskus rakennetaan) | Luku 1: Johdanto vihreään datakeskukseen; Luku 2, osio ”Miksi datakeskus rakennetaan” | Luku 1: Johdanto data- ja tekoälyohjattuun optimointiin (mitä optimoinnilla tavoitellaan) | liiketoiminta-, palvelu- ja regulaatiotarpeet, miksi oma datakeskus / konesali on olemassa; pohjustaa, miksi optimointi on järkevää |
| Oma datakeskus vs. pilvipalvelut (ratkaisuvaihtoehdot) | Luku 2, osio ”Oma datakeskus, kolmannen osapuolen konesali vai pilvipalvelut” | Luku 1: Johdanto (milloin käytön aikainen optimointi on omissa käsissä); tarvittaessa Luku 2: mittauspisteet eri ratkaisumalleissa | missä tilanteissa datan ja ohjauksen omistajuus mahdollistaa AI-pohjaisen optimoinnin (oma / colocation vs. pilvi) |
| Sijainnin tekniset tekijät (sähkö, verkko, ilmasto) | Luku 2, osio ”Sijainnin tekniset tekijät” | Luku 2: Datakeskus tekoälyn näkökulmasta (mittauspisteet sähkönsyötölle, verkolle, ulkolämpötilalle); Luku 3: Datan keruu ja yhdistäminen | sähkön saatavuus ja hinta, verkon latenssi ja kapasiteetti, ilmasto ja jäähdytystarve – nämä vaikuttavat siihen, millaista dataa myöhemmin saadaan malleille |
| Sijainnin ympäristö- ja energiatehokkuustekijät | Luku 2, osio ”Ympäristö ja energiatehokkuus sijaintipäätöksessä” | Luku 1: Johdanto (CO₂- ja energiatavoitteet); Luku 2: mittauspisteet uusiutuvan energian osuudelle ja hukkalämmölle; Luku 4: Case-tyyppiset käyttötapaukset energian ja päästöjen optimoinnista | uusiutuvan energian osuus, hukkalämmön hyödyntämismahdollisuudet, veden saatavuus – sijainti määrittelee optimoinnin potentiaalin |
| Riskit ja resilienssi (turvallisuus, vakaus, häiriöt) | Luku 2, osio ”Riskit ja resilienssi” | Luku 6: Jatkuva käytön aikainen optimointi, operointi ja riskienhallinta | fyysiset riskit (tulva, sähkökatkot, poliittinen riski) ja niiden merkitys myös AI-pohjaisen ohjauksen kannalta; varmistetaan, ettei optimointi heikennä resilienssiä |
| Tavoitetason määrittely (vihreys, PUE/CO₂-tavoitteet, mittarit) | Luku 1: Johdanto; Luku 7: EN 50600-4 -mittarit ja muut tunnusluvut | Luku 1: Johdanto (tavoitteiden asettaminen); Luku 3: Datan keruu ja perusanalytiikka (tavoitteiden seurantaa varten); Luku 6: Jatkuva optimointi ja mittaripohjainen päätöksenteko | tässä päätetään, millaisia mittareita (PUE, CO₂, WUE jne.) seurataan ja mihin syväoppimismalleja myöhemmin käytetään; luo raamit optimointityölle |

---

## (Valinnainen) Tarkempi kartta Moduuli 2:lle

| Moduuli 2: Vihreän datakeskuksen elementit | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|-------------------------------------------|------------------------|----------------------------|--------|
| Energianlähde                            | Luku 3, osio ”Energianlähde” | Luku 2: Mittauspisteet energianlähteeseen liittyen (esim. uusiutuvan energian osuus, sopimustiedot); luku 4: Case energianlähteen ja CO₂-intensiteetin optimoinnista | energialähteen valinta, uusiutuvan osuuden seuranta ja vaikutus CO₂:een |
| Energiatehokkuus                         | Luku 3, osio ”Energiatehokkuus” | Luku 2: IT- ja jäähdytyskuorman mittarit; luku 4: Case jäähdytyksen ja palvelinkuorman optimoinnista; luku 5: Ohjausstrategiat (asetukset, ohjauslogiikka) | lämpötilat, ilmavirrat, kuormanjako, konsolidointi, vaikutus PUE:hen |
| Hukkalämmön hyödyntäminen                | Luku 3, osio ”Hukkalämmön hyödyntäminen” | Luku 2: Lämmön mittarit (teho, lämpötilatasot); luku 4: Case hukkalämmön ohjauksesta (milloin ja minne lämpö ohjataan); luku 5: Ohjausstrategiat | lämpöteho, lämpötilatasot, kytkentävaihtoehdot, kysynnän mukaan ohjaaminen |
| Vedenkulutus                             | Luku 3, osio ”Vedenkulutus” | Luku 2: Vesijäähdytyksen ja vedenkulutuksen mittarit; luku 4: Case vedenkulutuksen vähentämisestä ilman riskien kasvua | WUE, jäähdytystapojen vertailu, vedenkulutuksen ja energiankulutuksen kompromissi |
| Hiilineutraalius ja raportointi          | Luku 3, osio ”Hiilineutraalius ja raportointi” | Luku 3: Datan keruu päästölaskentaa varten (CO₂-intensiteetti, kulutus); luku 4: Case hiilineutraaliustavoitteiden seuraamisesta mallien avulla; luku 6: Mittareiden ja tavoitteiden jatkuva seuranta | Scope 1–3 perusajatus, datalähteet, raportointiketju ja AI:n rooli trendien tunnistamisessa |
| Kiertotalous ja materiaalien hallinta    | Luku 3, osio ”Kiertotalous ja materiaalien hallinta” | Luku 6: Jatkuva optimointi ja laitekannan elinkaaren seuranta (esim. käyttöaste, ikä, energiatehokkuus) | laitteiden elinkaari, päivitysrytmi, poisto- ja kierrätysdata, energiatehokkuus vs. uusiminen |
| Sertifioinnit ja standardit              | Luku 3, osio ”Sertifioinnit ja standardit” | Luku 6: Jatkuva optimointi ja vaatimustenmukaisuus (mitä dataa AI ja mittarit voivat tuottaa sertifioinnin tueksi) | EN 50600, ISO 50001 jne., miten mittarointi ja AI helpottavat auditointeja |

---

## (Valinnainen) Tarkempi kartta Moduuli 3:lle

| Moduuli 3: Datakeskuksen elinkaaren vaiheet | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|--------------------------------------------|------------------------|----------------------------|--------|
| Esiselvitys (tarve, vaihtoehdot, vihreän tason tavoitteet) | Luku 4, osio ”Elinkaaren vaiheet – esiselvitys” | Luku 1: Johdanto optimointitavoitteisiin; Luku 2: Mittauspisteiden ja datatarpeen suunnittelu | määritellään energiatehokkuus-, CO₂- ja hukkalämpötavoitteet jo ennen suunnittelua |
| Suunnittelu (sijainti, kapasiteetti, perusratkaisut) | Luku 2: Sijaintipäätökset; Luku 4, osio ”Suunnitteluvaihe” | Luku 2: Mihin kaikkiin järjestelmiin asennetaan mittarit; Luku 3: Datan keruun arkkitehtuurin suunnittelu | suunnittelussa päätetään, mitä voidaan myöhemmin mitata ja optimoida (jäähdytys, sähkö, kuorma, hukkalämpö) |
| Rakentaminen (toteutus periaatteiden pohjalta) | Luku 4, osio ”Rakentaminen” | Luku 3: Datan keruun toteutus (mittareiden asennus, liitynnät järjestelmiin) | varmistetaan, että mittarit, lokit ja rajapinnat tulevat fyysisesti ja loogisesti paikoilleen |
| Käyttöönotto (testaus, ensimmäiset mittaukset) | Luku 4, osio ”Käyttöönotto” | Luku 3: Ensimmäinen datan keruu ja perusanalytiikka; Luku 4: Ensimmäiset mallit (esim. perusennuste kulutukselle) | baseline-mittaukset, vertailutavoitteiden asettaminen, ensimmäiset AI/ML-kokeilut turvallisesti |
| Käyttö ja operointi (normaali arki konesalissa) | Luku 4, osio ”Käyttö ja operointi” | Luku 4: Syväoppimisen käyttötapaukset (kulutus, jäähdytys, kuorma, hukkalämpö); Luku 5: Ohjausstrategiat; Luku 6: Jatkuva optimointi ja riskienhallinta | jatkuva mittaus, AI-mallit käytössä ohjauksen tukena, PUE/CO₂-seuranta, häiriöiden tunnistus |
| Modernisointi ja kapasiteetin laajennus | Luku 4, osio ”Modernisointi ja laajennukset” | Luku 3: Analytiikka päätöksenteon tukena (milloin päivitetään laitteita); Luku 6: Pitkän aikavälin trendit ja optimoinnin vaikutusten seuranta | päätetään, mitä kannattaa uusia energiatehokkuuden ja kapasiteetin kannalta; hyödynnetään historiadataa ja malleja |
| Purku ja elinkaaren loppu (kiertotalous) | Luku 4, osio ”Purku ja elinkaaren loppu”; Luku 3: Kiertotalous | Luku 6: Elinkaaritiedon hyödyntäminen (ikä, käyttöaste, energiatehokkuus) tulevien ratkaisujen suunnittelussa | miten opitaan vanhasta datakeskuksesta: mikä toimi, mikä ei, kiertotalous ja opit seuraavaan hankkeeseen |

---

## (Valinnainen) Tarkempi kartta Moduuli 4:lle

| Moduuli 4: Datakeskuksen toiminta vaiheittain | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|----------------------------------------------|------------------------|----------------------------|--------|
| Sähkönsyöttöketju (verkosta konesaliin ja kaapeille) | Luku 5, osio ”Sähkönsyöttö ja virranjakelu” | Luku 2: Mittauspisteet sähkönsyötössä (kokonaiskulutus, UPS, PDU); Luku 3: Kulutus- ja häviödatasta perusanalytiikka; Luku 4: Case sähkönsyötön hyötysuhteen ja kuormituksen optimoinnista | muuntajat, UPS, PDU:t, niiden häviöt ja kuormitus; missä syntyy sähköhävikkiä ja miten se tunnistetaan datasta |
| Jäähdytysjärjestelmät (ilma, neste, free cooling) | Luku 5, osio ”Jäähdytys ja lämpötilanhallinta” | Luku 2: Mittauspisteet jäähdytyksessä (lämpötilat, ilmavirrat, pumput, puhaltimet); Luku 3: Jäähdytyksen energiadatan analysointi; Luku 4: Case jäähdytyksen ja palvelinkuorman yhteisoptimoinnista; Luku 5: Ohjausstrategiat (asetusten säätö) | jäähdytyksen osuus kokonaiskulutuksesta, lämpötila-asetukset, ilmavirrat, free coolingin käyttö; AI/ML voi hakea asetuksia, jotka minimoivat kulutuksen lämpörajojen sisällä |
| Palvelinkuorma ja palvelimet (laskenta, virtualisointi, tallennus) | Luku 5, osio ”Palvelimet ja tallennus” | Luku 2: Mittauspisteet palvelinkuormalle (CPU, muisti, virrankulutus); Luku 4: Case palvelinkuorman sijoittelusta ja konsolidoinnista; Luku 5: Ohjausstrategiat (kuorman siirrot, sammuttaminen) | kuormanjako, idle-kapasiteetti, konsolidointi; syväoppimista voidaan käyttää ennustamaan kuormaa ja ehdottamaan energiatehokkaampaa sijoittelua |
| Verkkoliikenne ja reititys (pyyntö internetistä palvelimelle ja takaisin) | Luku 5, osio ”Verkko ja yhteydet” | Luku 2: Verkkolaitteiden ja liikenteen mittauspisteet (kuorma, virrankulutus); Luku 3: Verkkodatan analytiikka; tarvittaessa Luku 4: Case verkon ja palvelinkuorman yhteisvaikutuksesta | verkon kuormitus vaikuttaa osaltaan energiankulutukseen ja viiveisiin; datan perusteella voidaan tunnistaa turhat pullonkaulat ja ylikapasiteetti |
| Hukkalämpö polun lopussa (lämpö takaisin ympäristöön tai hyödynnettäväksi) | Luku 5, osio ”Lämmöstä hukkalämmöksi ja hyötykäyttöön”; linkittyy myös Luku 6: ”Energian kulutus ja hukkalämmön hyödyntäminen” | Luku 2: Mittauspisteet lämpöteholle ja lämpötilatasoille; Luku 4: Case hukkalämmön ohjauksesta (milloin ja minne lämpö ohjataan); Luku 5: Ohjausstrategiat (lämmönsyötön ohjaus kysynnän mukaan) | missä kohtaa ketjua lämpö kerätään talteen, kuinka paljon ja millä lämpötilalla; AI/ML voi optimoida hukkalämmön ohjausta kysynnän ja ulkoisten olosuhteiden perusteella |
| Mittaustiedon kulku ja integraatiot (BMS, DCIM, mittarit) | Luku 5, mahdollinen osio ”Valvonta ja hallintajärjestelmät” (tai viittaus luvun yleisesittelyyn) | Luku 2: Mittauspisteiden kartoitus ja järjestelmäkohtainen data; Luku 3: Datan yhdistäminen yhteiseen analytiikkakerrokseen; Luku 6: Jatkuva optimointi ja operointi | missä järjestelmissä data syntyy ja miten se saadaan AI-malleille; olennaista koko optimointioppaan kannalta |
| Palautesilmukat: miten ohjaus vaikuttaa energiankulutukseen | Luku 5 (viittaus ketjun kokonaiskuvaan) | Luku 4: Syväoppimisen käyttötapaukset (esim. asetusten vaikutus kulutukseen); Luku 5: Ohjausstrategiat; Luku 6: Riskienhallinta ja valvonta | osoittaa, että kyse ei ole vain seurannasta, vaan mallien tuottamasta palautesilmukasta: mallit tuottavat ehdotuksia ja ohjaus muuttaa järjestelmän käyttäytymistä |

---

## (Valinnainen) Tarkempi kartta Moduuli 5:lle

| Moduuli 5: Energian kulutus ja uudelleenkäyttö | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|-----------------------------------------------|------------------------|----------------------------|--------|
| Kokonaisenergiankulutus ja sen jakautuminen (IT vs. muu infrastruktuuri) | Luku 6, osio ”Energian kulutus datakeskuksessa” | Luku 1: Johdanto (tavoitteena kulutuksen ja CO₂:n pienentäminen); Luku 3: Datan keruu ja perusanalytiikka (kokonaiskulutus, IT vs. ei-IT) | peruskuva: mistä kWh:t syntyvät; optimointioppaan puolella data pilkotaan analysoitavaan muotoon |
| PUE ja muut energiatehokkuuden mittarit | Luku 6, osio ”PUE ja muut tehokkuusluvut”; linkittyy myös Luku 7: EN 50600-4 -mittarit | Luku 3: PUE- ja muiden mittarien laskenta datasta; Luku 4: Case PUE:n ennustamisesta ja optimoinnista; Luku 5: Ohjausstrategiat (miten mittareita käytetään säätöpäätöksissä) | PUE selitetään perusoppaassa intuitiivisesti, optimointioppaassa siitä tulee mallien keskeinen tavoitemuuttuja |
| IT-kuorman vaikutus energiankulutukseen | Luku 6, viittaus IT-kuorman osuuteen kokonaiskulutuksesta (yhdessä Luku 5:n palvelin-osion kanssa) | Luku 2: Mittauspisteet palvelinkuormalle (CPU, muisti, virta); Luku 4: Case IT-kuorman ja energiankulutuksen mallintamisesta; Luku 5: Ohjausstrategiat (kuorman siirrot, konsolidointi, sammuttaminen) | miten liikenne ja kuorma näkyvät kWh-luvuissa; AI voi oppia suhteita kuorman ja kulutuksen välillä |
| Jäähdytyksen energiankulutus ja sen suhteellinen osuus | Luku 6, osio ”Jäähdytyksen osuus energiankulutuksesta” | Luku 2: Mittauspisteet jäähdytyksessä (tehot, lämpötilat, ilmavirrat); Luku 3: jäähdytysjärjestelmän energiadatan analytiikka; Luku 4: Case jäähdytyksen optimoinnista IT-kuorman kanssa; Luku 5: Ohjausstrategiat (setpointit, free cooling, pumppujen/tuulettimien ohjaus) | usein suurin yksittäinen ei-IT-kuluerä; syväoppiminen voi etsiä energiatehokkaimmat lämpötila- ja virtausasetukset turvallisesti |
| Hukkalämmön synty ja potentiaali | Luku 6, osio ”Hukkalämpö ja sen potentiaali” | Luku 2: Mittauspisteet lämpöteholle ja lämpötilatasoille; Luku 3: Lämmön energiataseen analytiikka; Luku 4: Case hukkalämmön ohjauksesta (milloin lämpö hyödynnetään ja miten se vaikuttaa kokonaiskulutukseen ja CO₂:een) | perusoppaassa selitetään, mitä hukkalämmöllä tarkoitetaan; optimointioppassa mallit auttavat ohjaamaan lämpöä sinne, missä se tuottaa eniten hyötyä |
| Hukkalämmön hyödyntäminen käytännössä (kaukolämpö tms.) | Luku 6, konkreettiset esimerkit hukkalämmön hyödyntämisestä | Luku 4: Case hukkalämmön hyödyntämisen ohjauksesta (esim. dynaaminen ohjaus kysynnän, ulkolämpötilan ja energiahinnan mukaan); Luku 5: Ohjausstrategiat | AI/ML voi huomioida ulkoiset signaalit (lämpötilat, hinnat) ja päättää, milloin hukkalämmön hyödyntäminen on taloudellisesti ja ekologisesti optimaalisinta |
| Kulutusprofiilit ja kuormituksen ajallinen vaihtelu (päivä/viikko/vuosi) | Luku 6, mahdollinen osio ”Kulutusprofiilit ja kuormituksen vaihtelu” | Luku 3: Aikasarja-analytiikka ja kulutusprofiilit; Luku 4: Case kulutuksen ennustamisesta (ennusteet ohjaavat sekä kapasiteettia että energiankäyttöä) | syväoppiminen (esim. LSTM) voi ennustaa tulevaa kulutusta ja auttaa varautumaan sekä optimoimaan ajoitusta |
| Energiansäästötoimet ja niiden vaikutusten arviointi | Luku 6, osio ”Energiansäästötoimet” | Luku 3: Ennen–jälkeen-analytiikka; Luku 4: Case toimenpiteiden vaikutusten mallintamisesta; Luku 6: Jatkuva optimointi (säännöllinen seuranta ja näkyvyys saavutettuihin hyötyihin) | perusopas listaa tyypillisiä toimenpiteitä; optimointiopas näyttää, miten dataa ja malleja käytetään vaikutusten todentamiseen |
| Yhteys CO₂-päästöihin ja raportointiin | Luku 6 & Luku 7: EN 50600-4 -mittarit ja CO₂-sidonnaiset tunnusluvut | Luku 1: Johdanto (CO₂ vähentäminen keskeinen tavoite); Luku 3: Energiankulutuksen ja päästöintensiteetin yhdistäminen; Luku 4: Case CO₂-optimoinnista; Luku 6: Jatkuva mittaripohjainen seuranta | energian käytön ja päästöjen yhteys tehdään näkyväksi; AI voi auttaa tunnistamaan, mitkä toimet vähentävät CO₂:ta eniten |

---

## (Valinnainen) Tarkempi kartta Moduuli 6:lle

| Moduuli 6: EN 50600-4 -standardi ja mittarit | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|---------------------------------------------|------------------------|----------------------------|--------|
| EN 50600-4 -standardin rooli ja perusidea | Luku 7, osio ”EN 50600-4 ja sen tarkoitus” | Luku 1: Johdanto (mittareiden rooli optimoinnin tavoitteiden määrittelyssä); Luku 6: Jatkuva optimointi ja mittaripohjainen seuranta | mitä standardi tekee, miksi se on olemassa, miten se liittyy vihreään konesaliin ja raportointiin |
| PUE (Power Usage Effectiveness) – peruskäsite | Luku 7, osio ”PUE – energiatehokkuuden perusmittari” | Luku 3: PUE:n laskenta datasta; Luku 4: Case PUE:n ennustamisesta ja optimoinnista; Luku 5: Ohjausstrategiat (mittari ohjauksen tavoitteena) | perusoppaassa selitetään intuitiivisesti, optimointioppaassa PUE toimii mallien tavoitteena ja vertailulukuna |
| CUE (Carbon Usage Effectiveness) ja CO₂-intensiteetti | Luku 7, osio ”CUE ja hiili-intensiteetti” | Luku 3: Energiankulutuksen ja päästöintensiteetin yhdistäminen; Luku 4: Case CO₂-optimoivasta ohjauksesta; Luku 6: CO₂-trendien seuranta | yhdistää energiankulutuksen ja päästökerroin-tiedon; AI/ML voi optimoida kohti matalampaa CUE:ta |
| WUE (Water Usage Effectiveness) – vedenkäytön mittari | Luku 7, osio ”WUE ja vedenkulutus” (linkittyy Luku 3:n vedenkulutuskohtaan) | Luku 2: Mittauspisteet vesijäähdytykselle ja vedenkulutukselle; Luku 3: WUE-laskenta ja trendit; Luku 4: Case vedenkulutuksen vähentämisestä | miten vedenkulutus suhteutuu IT-kuormaan; optimointioppaassa tasapaino vedenkulutuksen, energian ja riskien välillä |
| Muut EN 50600-4 -mittarit (REF/ERF, CER tms.) | Luku 7, osio ”Muut keskeiset mittarit” | Luku 3: Mittarien laskenta ja datakenttien yhdistäminen; Luku 4: Case: usean mittarin yhtäaikainen optimointi; Luku 6: Mittareiden käyttö KPI-järjestelmänä | perusoppaassa kevyet määritelmät, optimointioppaassa mittarit muodostavat “mittaripaketin”, jota mallit seuraavat |
| Mittauspisteet ja datalähteet mittareille | Luku 7, viittaus siihen, mistä mittareiden tarvitsemat luvut periaatteessa tulevat (yhteys Luku 5 ja 6 sisältöön) | Luku 2: Datakeskus tekoälyn näkökulmasta (mittauspistekartta); Luku 3: Datan yhdistäminen yhteiseen analytiikkaan | tärkeä silta: mittareita ei voi laskea ilman oikeita mittauspisteitä; optimointiopas näyttää tarkasti, mistä mikäkin tieto tulee |
| Mittaustiheys, historian pituus ja datan laatu | Luku 7, mahdollinen osio ”Mittaroinnin perusperiaatteet” | Luku 3: Aikasarja-analytiikka, mittaustiheyden ja historiadatan merkitys; Luku 6: Jatkuvan seurannan käytännön järjestelyt | kuinka usein mittarit päivitetään, kuinka pitkää historiaa mallit tarvitsevat, mitä tehdään puuttuville arvoille |
| Mittarit raportoinnissa ja tavoitteiden asettamisessa | Luku 7, osio ”Mittarit johtamisen ja raportoinnin välineinä” | Luku 1: Johdanto (tavoitteiden kytkentä mittareihin); Luku 6: Mittareihin perustuva päätöksenteko ja kehityspolut | perusopas: johdolle ja raporteille; optimointiopas: miten mittaritasot käännetään konkreettisiksi ohjaus- ja optimointitavoitteiksi |
| Mittarit AI-/ML-malleissa (tavoitteet, rajoitteet, palautesilmukat) | Luku 7, lyhyt maininta mittareiden käytöstä kehittämisen tukena | Luku 4: Syväoppimisen käyttötapaukset (mittarit mallin tavoitemuuttujina); Luku 5: Ohjausstrategiat (mittarit raja-arvoina ja optimoinnin tavoitteina); Luku 6: Palautesilmukat (mittaritulokset → mallien ja asetusten säätö) | yhdistää mittarit konkreettisesti AI/ML-malleihin: mitä malli yrittää minimoida/maksimoida ja miten tuloksia käytetään ohjauksessa |

---

