

## P1 – Johdanto vihreään datakeskukseen

### P1.1 Miksi perusopas?

Tämä perusopas tukee vihreän datakeskuksen suunnittelua ja toteutusta Suomessa. Opas jäsentää päätökset vaiheisiin ja liittää ne mitattaviin suureisiin: energia (E), teho (P), kapasiteetti (C) ja palvelutaso (SLA/SLO) (Jin et al., 2016; Uddin & Rahman, 2012; Geng, 2015). Väitteet sidotaan lähteisiin.

Opas etenee luvuittain seuraavasti:

Luku 2: Datakeskuksen rakentamisen syyt ja sijaintipäätösten perusteet
Sijainnin reunaehdot: sähkö, verkko, viive, jäähdytys ja hukkalämpöliitynnät.

Luku 3: Vihreän datakeskuksen peruselementit ja periaatteet
Osa-alueet ja käsitteet, joilla vihreyttä tarkastellaan; mittausrajat ja arvioinnin periaatteet.

Luku 4: Datakeskuksen elinkaaren vaiheet
Suunnittelu, rakentaminen, käyttö ja käytöstäpoisto; data ja materiaalivirrat.

Luku 5: Datakeskuksen toiminta vaiheittain
Kuorma ja palvelutaso → kapasiteettisuunnittelu → IT-tehon vaihtelu ajassa → sähköliittymän, jakelun, varmistuksen ja jäähdytyksen mitoitus.

Luku 6: Energian kulutus ja uudelleenkäyttö
Kulutuserät, jäähdytyksen sähkönkulutus, hukkalämmön talteenotto, rajapinnat ja mittaustieto.

Luku 7: Datakeskusten energiatehokkuuden mittaaminen
EN 50600-4 -mittarit ja mittauspisteet; mittarikortit (PUE, REF, ERF, CER, CUE, WUE).

Merkinnät ja mitoitusketjun symbolit esitellään kohdassa P1.4.

### P1.2 Mikä on vihreä datakeskus?

Vihreä datakeskus on datakeskus, jossa suunnittelu ja operointi sidotaan energian ja päästöjen mittaamiseen sekä raportointiin (Uddin & Rahman, 2012). Tässä oppaassa vihreys kuvataan kokonaisenergiankulutuksena, energiatehokkuusmittareina ja päästöintensiteettinä (Jin et al., 2016; Geng, 2015). Vihreä datakeskus käsitellään seuraavina osa-alueina:

Kuorma ja kapasiteetti: työkuorman kuvaus, kapasiteetin mitoitus ja IT-tehon vaihtelu ajassa.

Sähkönsyöttö ja varmistus: sähköliittymä, jakelu, UPS/varavoima ja häviöt.

Sähkön alkuperä ja päästöt: hankintatapa, todentaminen ja päästökertoimet raportointiin.

Jäähdytys: jäähdytysarkkitehtuuri ja jäähdytyksen sähkönkulutus suhteessa IT-tehoon.

Hukkalämpö: talteenotto, mittaus ja luovutusrajapinta.

Elinkaaren loppu: käytöstäpoisto, tietojen hävittäminen ja materiaalivirrat.
   
Osa-alueiden päätökset kuvataan kohdassa P1.8 ja toteutus käsitellään luvussa 3.

### P1.3 Miten opasta käytetään?

Opas on kirjoitettu päätöksenteon ja dokumentoinnin tueksi. Käytä opasta siten, että etenet kysymyksestä päätökseen ja päätöksestä mitattaviin lähtötietoihin.

Määritä lähtötiedot ja rajaukset. Kirjaa työkuorman ja palvelutason vaatimukset sekä mittausrajat (mistä kokonaisenergia mitataan ja mihin asti IT-energia rajataan).

Johda mitoitusketju. Johda työkuormasta kapasiteetti ja IT-tehon vaihtelu ajassa, ja mitoita niiden perusteella sähköliittymä, jakelu, varmistus ja jäähdytys. Ketjun merkinnät ja suureet esitellään kohdassa P1.4.

Valitse mittarit ja todennus. Valitse mittarit ja määritä mittauspisteet sekä dokumentoi sähkön alkuperän todentaminen ja päästökertoimet raportointia varten.

Kun toteutus on käynnissä, käytä menettelyä: mittaa → analysoi → muutos → todenna → vakioi.


### P1.4 Datakeskuksen sähkö- ja jäähdytysinfrastruktuurin tehomitoitusketju

#### Perustermit ja yksiköt

* **Teho `P`**: hetkellinen sähköteho. Yksikkö W, kW, MW.

* **Energia `E`**: teho aikajaksolla. Yksikkö Wh, kWh, MWh, GWh. (Esim. `kWh = kW × h`.)

* **IT-työkuorma `L(t)`**: datakeskukseen saapuvien palvelu- ja työpyyntöjen määrä ja ominaisuudet ajan funktiona (esim. pyyntöä/s, transaktiota/s, jobeja/eräajoja, datavirtoja).

* **SLA (Service Level Agreement)**: **sopimus / sitoumus** palvelutasosta, jossa määritellään yksi tai useampi SLO sekä mittaus- ja raportointikäytäntö ja mahdolliset seuraamukset (esim. hyvitykset), jos taso ei toteudu; omassa datakeskuksessa “asiakas” on usein **sisäinen** (liiketoiminta, palvelun omistaja tai toinen tiimi).

* **SLO (Service Level Objective)**: yksittäisen palveluominaisuuden **mitattava tavoitetaso** (esim. saatavuus, vasteaika, virheosuus) tietyllä aikajaksolla; määritellään numeerisena tavoitteena ja mittaustapana (esim. 99,9 %/kk tai p95 < 200 ms).

* **Palvelutasovaatimus mitoituksessa**: mitoitus johdetaan käytännössä SLO-tavoitteista (mitä pitää saavuttaa), kun taas SLA on niiden sopimusmuotoinen sitoumus (kenelle ja millä ehdoilla).

* **Laskentakapasiteetti (IT-kapasiteetti)**: IT-resurssit, joilla `L(t)` suoritetaan sovituilla palvelutasoilla (palvelimet, CPU/GPU, muisti, tallennus, verkko). Kapasiteetti on kapasiteettisuunnittelun tulos. (Wang et al., 2020)

  * **Asennettu kapasiteetti `C_inst`**: hankittu ja asennettu resurssipooli (teoreettinen enimmäistaso).
  * **Aktiivinen kapasiteetti `C_act(t)`**: se osa resurssipoolista, joka pidetään käytössä ajanhetkellä `t` (aktiiviset palvelimet ja niiden resurssit).
  * **Varakapasiteetti `C_res`**: kapasiteetti, jota pidetään käytettävissä kuormahuippujen, ennusteen epävarmuuden tai vikatilanteiden varalta (SLA/SLO ja varmistusperiaate). (Whitney & Delforge, 2014; Wang et al., 2020)

* **IT-teho `P_IT(t)`**: IT-laitteiden (palvelimet, tallennus, verkko) ottama sähköteho ajanhetkellä `t`. Yksikkö kW (IT).

* **Lämpökuorma / jäähdytyskuorma `Q_th(t)`**: poistettava lämpöteho tilasta tai jäähdytyspiiristä. Yksikkö kW(th). Käytännön mitoituksessa `Q_th(t)` määräytyy IT-tehon ja muiden sähkökuormien (ml. sähköketjun häviöt) perusteella. (Geng, 2015)

* **Jäähdytyksen sähköteho `P_cool(t)`**: jäähdytysjärjestelmän (esim. chillerit, pumput, puhaltimet, CRAH/CRAC) ottama sähköteho. Yksikkö kW(e). Huomio: `P_cool(t)` (sähköteho) ja `Q_th(t)` (poistettava lämpöteho) ovat eri suureita. (Geng, 2015)


#### Tehomitoitusketju

Tehomitoitusketju tarkoittaa päätöksentekoketjua, jossa IT-työkuorman `L(t)` sekä palvelutasotavoitteiden (SLO) ja niistä johdettujen palvelutasositoumusten (SLA) perusteella määritetään vaiheittain datakeskuksen tarvittava sähkö- ja jäähdytysteho. Ketju etenee tyypillisesti IT-kuormasta (palvelimet, tallennus, verkko) kokonaistehoon ja edelleen infrastruktuurin mitoitukseen (sähköliittymä, UPS ja varavoima, sähkönjakelu sekä jäähdytysjärjestelmät). Saatavuus- ja toipumisvaatimukset (esim. redundanssi N+1/2N, RTO/RPO) kasvattavat mitoitusvaraa ja ohjaavat rakenteellisia valintoja. (Geng, 2015; Wang et al., 2020)

Ketju esitetään seuraavasti:

`L(t)` + (SLA/SLO, saatavuus) → `C_act(t)` (+ `C_res`) → `P_IT(t)` → sähkö- ja jäähdytysinfrastruktuurin mitoitus

* `L(t)` + SLA/SLO (+ saatavuus) → `C_act(t)` (+ `C_res`): kuorman määrä ja vaihtelu sekä palvelutasoehdot määrittävät, kuinka suuri osa `C_inst`:stä pidetään aktiivisena ja kuinka paljon kapasiteettia pidetään varalla. (Whitney & Delforge, 2014; Wang et al., 2020)
* `C_act(t)` → `P_IT(t)`: aktiivisten resurssien määrä ja kuormitusaste muodostavat IT-tehoprofiilin, joka toimii sähkö- ja jäähdytysjärjestelmien mitoituksen lähtötietona. (Geng, 2015; Wang et al., 2020)
* `P_IT(t)` → infrastruktuurin mitoitus: IT-teho ja siihen liittyvät häviöt määrittävät sähköketjun mitoitustehoja (liittymä, UPS, jakelu) sekä lämpökuorman `Q_th(t)`, jonka perusteella jäähdytysjärjestelmät mitoitetaan. (Geng, 2015)

**Varmistusperiaate (esim. N+1, 2N)** tarkoittaa, että infrastruktuuri mitoitetaan siten, että kuorma voidaan ylläpitää myös yksittäisen komponentin vikaantuessa. Tämä näkyy sekä asennettuna infrastruktuurikapasiteettina että osakuormalla toimivien laitteiden hyötysuhteina. (Geng, 2015; Whitney & Delforge, 2014)


#### Huomio (vihreä tarkastelu)

Tässä oppaassa sama tehomitoitusketju säilyy, mutta hankkeessa määritetään lisäksi:

1. **sähkön alkuperän todentaminen**,
2. **energian käytön mittausrajat**, ja
3. **hukkalämmön talteenoton ja hyötykäytön rajapinnat**. (Jin et al., 2016; Uddin & Rahman, 2012)

**Mittausrajalla** tarkoitetaan, mistä pisteestä kokonaisenergia mitataan (esim. sähköliittymä / pääkeskus) ja mistä pisteestä IT-energia mitataan (esim. UPS/PDU-lähdöt tai räkki-/PDU-mittaus). Rajaus määrittää, mitkä häviöt ja kuormat sisältyvät energiatehokkuuslukuihin (esim. PUE). (Jin et al., 2016; Uddin & Rahman, 2012)


### P1.5 Tausta: perinteisen datakeskuksen energian- ja laitemitoitus

P1.4 määritteli tehomitoitusketjun muodossa:

`L(t)` + (SLA/SLO, saatavuus) → `C_act(t)` (+ `C_res`) → `P_IT(t)` → sähkö- ja jäähdytysinfrastruktuurin mitoitus. (Geng, 2015; Wang et al., 2020)

Tässä kappaleessa tarkennetaan ketjun alkupäätä eli sitä, miten **saapuvista työpyynnöistä** muodostetaan kuvanus työkuormasta `L(t)` ja miten tämän perusteella johdetaan kapasiteettisuunnittelun päätökset (`C_act(t)`, `C_res`) ja niistä edelleen IT-tehoprofiili `P_IT(t)`. (Wang et al., 2020)


#### Keskeiset termit (katso myös sanasto, s. X)

- **Työpyyntö (job)**: yksittäinen suoritettava tehtävä tai pyyntö, jolle määritetään resurssitarpeet ja aikavaatimus. (Wang et al., 2020)
- **IT-työkuorma `L(t)` (workload)**: työpyyntöjen määrä ja ominaisuudet ajan funktiona (esim. työpyyntöjä/aikaväli, pyyntöä/s, transaktiota/s) sekä kuorman vaihtelu ja huiput. (Wang et al., 2020)
- **Työtyyppien muodostus (workload characterization)**: työpyyntöjen ryhmittely työtyypeiksi ja työtyyppikohtaisten resurssiprofiilien kuvaus. (Wang et al., 2020)
- **Kuorman ennuste (workload prediction)**: työpyyntöjen määrän (ja tarvittaessa työtyyppijakauman) ennustaminen tuleville aikajaksoille historiadatan perusteella. (Wang et al., 2020)
- **Palvelutasovaatimus (SLA/SLO, saatavuus)**: ehto, jonka puitteissa työpyyntö käsitellään (esim. vasteaika, määräaika) ja jonka perusteella kapasiteettia pidetään käytössä ja/tai varalla. (Wang et al., 2020)
- **Kelpoisuussidonta (job–server mapping)**: sääntö, jolla määritetään, millä palvelin-/resurssityypeillä työpyyntö voidaan suorittaa (esim. CPU-, muisti- ja laitevaatimukset). (Wang et al., 2020)
- **Kapasiteettisuunnittelu**: päätös siitä, mitkä resurssit pidetään käytössä `C_act(t)` (ja mitä pidetään varalla `C_res`) sekä miten työpyynnöt sijoitetaan niin, että resurssirajat ja SLA/SLO täyttyvät. (Wang et al., 2020)

#### Lähtötieto perinteisessä mitoituksessa

Perinteinen mitoitus perustuu usein historiadataan ja sen avulla kuvattuihin työpyyntöihin ja kuormituskäyttäytymiseen. Yksi tapa esittää tämä on erottaa (i) työtyyppien muodostaminen (workload characterization) ja (ii) kuorman ennustaminen (workload prediction) (Wang et al., 2020).

Työkuorma tyypitetään klusteroimalla, jolloin saadaan joukko työtyyppejä ja niiden tyyppijakauma (Wang et al., 2020). IT-työkuorma ennusteessa tulevien aikajaksojen työpyyntöjen määrää ennustetaan aikasarjamallilla, jolloin saadaan arvio työpyyntöjen määrästä per aikaväli (Wang et al., 2020). Tällöin kapasiteettiperusta voidaan ilmaista muodossa: **ennustettu työpyyntöjen määrä + työtyyppien resurssiprofiilit** (Wang et al., 2020).

Kun työtyypit ja palvelutasovaatimukset on kuvattu, palvelintarve johdetaan työpyyntöjen resurssivaatimuksista ja aikavaatimuksista (deadline/SLA/SLO). Työtyypit sidotaan niihin palvelintyyppeihin, joilla työpyyntö voidaan ajaa (job–server mapping), ja kapasiteetin mitoitus voidaan muotoilla kokonaislukusuunnitteluongelmana (ILP) (Wang et al., 2020). Koska vastaavat ongelmaluokat kytkeytyvät bin packing -tyyppisiin pakkausongelmiin, käytännön mitoituksessa käytetään usein heuristiikkoja täsmäratkaisun sijaan (Garey & Johnson, 1979; Wang et al., 2020).

#### Vaihtoehtoinen lähtötieto: sovellus- ja alustataso

Toinen perinteinen mitoitus perustuu sovellus- ja alustatasoon, jonka kapasiteettisuunnittelu kytketään palveluarkkitehtuuriin ja kasvuennusteisiin, ja mitoituksessa huomioidaan myös järjestelmäuudistusten siirtymävaiheet (refresh capacity) (Geng, 2015). Sähkötehon mitoituksessa erotetaan pätöteho (W), loisteho (VAR), näennäisteho (VA) ja tehokerroin (PF), koska kuorman sähköinen luonne vaikuttaa verkosta ja varavoimasta tarvittavaan kapasiteettiin (Geng, 2015).

#### Yhteenveto

Perinteinen datakeskus voidaan mitoittaa joko (a) sovellus- ja alustatasosta tai (b) ennustetuista työpyynnöistä, työtyypeistä ennusteista. Molemmissa tapauksissa lopputuloksena johdetaan IT-teho (kW), jonka varaan sähkö- ja jäähdytysinfrastruktuuri mitoitetaan (Geng, 2015; Wang et al., 2020).


### P1.6 Perinteisten datakeskusten käyttöaste ja IT-laitteiden sähkönkulutuksen kuormariippuvuus

Käyttöaste vaikuttaa tehonkulutukseen ja sitä kautta energiankulutukseen, koska IT-laitteiden teho koostuu kuormaan sidotusta osasta ja kuormasta riippumattomasta perustehosta. Katsauksissa perinteisten yritysdatasalien käyttöaste on raportoitu matalaksi ja hyperskaalan korkeammaksi, kun kuormia voidaan konsolidoida ja ohjata laajassa resurssipoolissa (Whitney & Delforge, 2014). 

Käyttöastetta laskevat kuorman vaihtelu ja kuorman ennustamisen epävarmuus (workload, workload prediction) sekä palvelutasovaatimukset (SLA/SLO/deadline), joiden vuoksi kapasiteettisuunnittelussa pidetään varakapasiteettia (Whitney & Delforge, 2014; Wang et al., 2020). Lisäksi saatavuusvaatimukset näkyvät infrastruktuurissa varmistusratkaisuina (esim. N+1, 2N), jotka lisäävät jatkuvasti valmiina pidettävää laite- ja järjestelmäkantaa sekä niiden aiheuttamaa perustason sähkönkulutusta (Whitney & Delforge, 2014).

Palvelinten sähkönkulutus ei historiallisesti ole ollut täysin energiaproportionaalista: tyhjäkäynnillä ja matalalla käyttöasteella sähkönkulutus ei alene samassa suhteessa kuin kuormitus (Barroso & Hölzle, 2007; Whitney & Delforge, 2014). Tämän vuoksi kapasiteetin mitoitus ja kuormanohjaus vaikuttavat suoraan datakeskuksen energiankulutukseen ja siitä johdettuihin päästöihin (Jin et al., 2016; Whitney & Delforge, 2014).


### P1.7 Kansainvälinen kehitys ja Suomen reunaehdot

Datakeskuksia rakennetaan digitalisaation, pilvipalvelujen ja verkottuneiden sovellusten IT-kapasiteetin (laskenta-, tallennus- ja verkkokapasiteetti) toteuttamiseksi. Samalla hajautettuja ja teknisesti vanhentuneita ympäristöjä korvataan keskistetyillä ratkaisuilla, joissa kapasiteettia ja operointia voidaan ohjata järjestelmätasolla (Jin et al., 2016; Shehabi et al., 2016). Datakeskusten osuus maailman sähkönkulutuksesta on ollut suuruusluokkaa noin yksi prosentti, vaikka laskentakapasiteetti ja datamäärät ovat kasvaneet (Masanet et al., 2020). Skenaarioissa on arvioitu, että ilman lisätoimia ICT-sektorin sähkönkäyttö voi kasvaa useisiin prosentteihin maailman kokonaiskulutuksesta, jos liikennemäärät ja kuormat jatkavat kasvuaan (Andrae & Edler, 2015). Uudemmissa tarkasteluissa on nostettu esiin myös suuritehoisen laskennan ja generatiivisen tekoälyn kuormien vaikutus energiatiheyksiin ja käyttöönoton nopeuteen (Sabree, 2025; Masanet et al., 2020).

Datakeskuksen käyttöaikaisia kasvihuonekaasupäästöjä voidaan arvioida kertomalla datakeskuksen käyttämä sähköenergia (kWh) käytetyn sähkön päästökertoimella (kgCO₂e/kWh). Tämä kattaa sähkönkulutukseen liittyvän osuuden; laajemmassa hiilijalanjälkirajauksessa voidaan lisäksi huomioida mm. varavoiman polttoaine, jäähdytyksen kylmäainepäästöt sekä laitteiden ja rakennuksen elinkaaren aikaiset päästöt. (Jin et al., 2016; Sabree, 2025)


### P1.8 Vihreän datakeskuksen elementit ja päätöspisteet
Tässä perusoppaassa vihreändatakeskuksen toteutus jäsennetään päätöspisteiksi. Päätökset esitetään muodossa päätös → tuotos → luku, jotta etenemisjärjestys ja kunkin vaiheen tulokset näkyvät yhdestä paikasta. Osa-alueet on kuvattu kohdassa P1.2 ja mitoitusketjun merkinnät kohdassa P1.4.

Kirjallisuudessa vihreä datakeskus kytkee IT-, sähkö- ja jäähdytysjärjestelmät energian ja ympäristövaikutusten mittaamiseen sekä seurantaan, ja tarkastelu esitetään tyypillisesti mittareina ja osa-alueina (kuorma–kapasiteetti, sähköketju, jäähdytys, hukkalämpö, todentaminen) (Uddin & Rahman, 2012; Jin et al., 2016; Geng, 2015; Wang et al., 2020; Barroso & Hölzle, 2007).

Tämä perusopas tuo samaan kokonaisuuteen päätös→tuotos→luku-rakenteen, jotta mitoitusketju ja mittausrajat voidaan viedä suunnittelusta toteutukseen ja raportointiin ilman, että lähtötietoja kootaan useista eri kohdista.

Päätökset (päätös → tuotos → luku)

Sijainti → sähkö-, verkko- ja liityntäehdot (jäähdytys ja hukkalämpö), viive- ja saatavuusrajat → Luku 2

Työkuorma ja palvelutaso (SLA/SLO) → kuormakuvaus L(t) ja palvelutasorajat (vasteajat/saatavuus/deadline) → Luku 5 (Wang et al., 2020)

Kapasiteetti → C_inst, C_act(t) ja C_res(t) (asennettu, käytössä pidettävä, varalla pidettävä) → Luku 5 (Wang et al., 2020)

IT-tehoprofiili → P_IT(t) (IT-teho ajan funktiona; huiput ja niiden kesto) → Luku 5 (Barroso & Hölzle, 2007; Wang et al., 2020)

Sähköketju ja varmistus → liittymäteho, jakelu, UPS/varavoima, varmistusperiaate (N / N+1 / 2N) ja häviöiden huomiointi → Luku 5 (Geng, 2015; LVM, 2020)

Sähkön alkuperä ja päästöt → todentamistapa (hankintamalli) ja päästökertoimien valinta raportointiin → Luku 6 (Jin et al., 2016; LVM, 2020)

Jäähdytysratkaisu → jäähdytysarkkitehtuuri ja jäähdytyksen sähköteho P_cool(t); mitoituksen lähtötiedot (lämpökuorma ja olosuhteet) → Luku 6 (Geng, 2015; Elavarasi et al., 2025)

Jäähdytyksen mittaus → mittauspisteet ja aikasarjat (jäähdytyksen sähkö, lämpötilat, virtaus/ilmamäärä) IT-kuorman vertailuun → Luku 7 (Geng, 2015; Elavarasi et al., 2025)

Hukkalämpö → rajapinta, mitattava lämpöenergia (MWh), toimitusvastuut ja sopimuslähtötiedot → Luku 6 (Geng, 2015; LVM, 2020)

Mittausrajat, mittarit ja raportointi → mittausrajat, mittarit (PUE, REF, ERF, CER, CUE, WUE), mittauspisteet ja dokumentoidut laskentasäännöt → Luku 7 (Uddin & Rahman, 2012; Jin et al., 2016; Geng, 2015)

Elinkaaren loppu → käytöstäpoisto, tietojen hävittäminen ja materiaalivirrat (prosessit ja vastuut) → Luku 4 (Geng, 2015)

Huom: jäähdytysratkaisujen vaihtoehdot ja valintaperusteet (esim. ekonomaiseri, hybridi, direct-to-chip, immersio) käsitellään luvussa 6. Mittareiden mittauspisteet ja laskentasäännöt käsitellään luvussa 7.


### P1.9 Miksi sijainti käsitellään ennen ratkaisujen valintaa

Luku 2 käsittelee rakentamisen syitä ja sijaintipäätöksiä, koska sijainti määrittää useita tämän oppaan myöhempiä reunaehtoja. Sijaintipäätöksessä tarkastellaan sähköverkon kapasiteettia ja luotettavuutta, palvelutasoon liittyviä vaatimuksia (mm. saatavuus ja redundanssi), sähkön päästöintensiteettiä ja uusiutuvan energian todentamista sekä jäähdytys- ja hukkalämpöratkaisujen edellyttämiä liityntöjä ja infrastruktuuria (Geng, 2015; Jin et al., 2016; LVM, 2020). Lisäksi sijainti kytkeytyy viive- ja käyttäjävaatimuksiin: kuorman siirto alueiden välillä on mahdollista vain, jos palvelutaso sallii viiveen ja saatavuuden näkökulmasta (Wang et al., 2020; Jin et al., 2016).


## Lähteet (APA)

Andrae, A. S. G., & Edler, T. (2015). On global electricity usage of communication technology: Trends to 2030. *Challenges, 6*(1), 117–157.

Barroso, L. A., & Hölzle, U. (2007). The case for energy-proportional computing. *Computer, 40*(12), 33–37.

Elavarasi, J., Thilagam, T., Amudha, G., Saratha, B., Ananthi, S. N., & Siva Subramanian, R. (2025). Green data centers: Advancing sustainability in the digital era. In *Proceedings of the International Conference on Trends in Material Science and Inventive Materials (ICTMIM-2025)* (pp. 1817–1823). IEEE.

Garey, M. R., & Johnson, D. S. (1979). *Computers and intractability: A guide to the theory of NP-completeness*. W. H. Freeman.

Geng, H. (Ed.). (2015). *Data center handbook*. John Wiley & Sons.

Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). Green data centers: A survey, perspectives, and future directions. *arXiv*. (arXiv:1608.00687)

LVM. (2020). *The ICT sector, climate and the environment – Interim report* (Publications of the Ministry of Transport and Communications 2020:14). Ministry of Transport and Communications, Finland.

Masanet, E., Shehabi, A., Lei, N., Smith, S., & Koomey, J. (2020). Recalibrating global data center energy-use estimates. *Science, 367*(6481), 984–986.

Sabree, R. M. S. (2025). Achieving sustainability in computing by minimizing data center carbon footprints. *Journal of Information Processing and Management*.

Shehabi, A., Smith, S. J., Sartor, D., Brown, R., Herrlin, M., Koomey, J. G., Masanet, E., Horner, N., Azevedo, I. L., & Lintner, W. (2016). *United States data center energy usage report*. Lawrence Berkeley National Laboratory.

Uddin, M., & Rahman, A. A. (2012). Energy efficiency and low carbon enabler green IT framework for data centers considering green metrics. *Renewable and Sustainable Energy Reviews, 16*(6), 4078–4094.

Wang, J., Palanisamy, B., & Xu, J. (2020). Sustainability-aware resource provisioning in data centers. In *2020 IEEE 6th International Conference on Collaboration and Internet Computing (CIC)* (pp. 60–67). IEEE. `https://doi.org/10.1109/CIC50333.2020.00018`

Whitney, J., & Delforge, P. (2014, August). *Data center efficiency assessment: Scaling up energy efficiency across the data center industry: Evaluating key drivers and barriers* (Issue Paper IP:14-08-a). Natural Resources Defense Council (NRDC) & Anthesis. `https://www.nrdc.org/sites/default/files/data-center-efficiency-assessment-IP.pdf`



# Perusopas vihreän datakeskuksen rakentamiseksi Suomessa
## P2 – Miksi datakeskus rakennetaan ja miten sijainti valitaan
Datakeskusten määrä ja koko kasvavat pilvipalveluiden ja digitaalisten palveluketjujen vuoksi. Samalla datakeskusten energiankulutus ja siitä seuraavat kustannus- ja päästövaikutukset ovat nousseet keskeiseksi suunnittelukriteeriksi. Merkittävä osa nykyisestä energiankulutuksesta ei johdu vain laskentakuorman kasvusta, vaan myös rakenteellisesta tehottomuudesta: resursseja ylivarmistetaan, kapasiteettia pidetään varalla ja käyttöaste jää matalaksi, mikä kasvattaa myös jäähdytyksen ja sähkönjakelun “tyhjäkäyntiä” [1].

Yhdysvaltain datakeskusten sähkönkulutus oli 2013 noin 91 mrd kWh ja ennuste 2020 noin 140 mrd kWh, ja globaalisti datakeskusten sähkönkulutuksen osuuden on arvioitu kasvavan merkittävästi [1]. Lisäksi tutkimusviitteet korostavat käyttöasteongelmaa: tyypillisiä palvelinkäyttöasteita on raportoitu noin 6–12 % tasolla, kun taas parhaat toimijat ovat pystyneet nostamaan käyttöastetta selvästi korkeammaksi (esim. 20–40 %) [1]. Tämä tarkoittaa sähkö- ja jäähdytysinfran näkökulmasta, että “vihreän datakeskuksen” rakentamisen keskeinen perustelu on usein saman palvelukyvyn tuottaminen pienemmällä energialla, joko parantamalla käyttöastetta (konsolidointi, virtualisointi, kuormanohjaus) tai pienentämällä infrastruktuurin häviöitä ja jäähdytyksen tarvetta – mielellään molempia [1]. 
Jin ym. (2016) jäsentävät vihreät ratkaisut kahteen pääluokkaan: (1) suunnittelu- ja rakennusvaiheen “vihreät laitteet ja infrastruktuuri” sekä (2) operoinnin aikaiset tehokkuus- ja optimointimenetelmät (energiatehokkuus, resurssien hallinta, lämpötilan ja jäähdytyksen ohjaus, mittarointi). arXiv Oppaan näkökulmasta tämä on tärkeä periaate: sijainti ja sähköinen infrastruktuuri luovat tehokkuuskaton, mutta operointi ratkaisee, päästäänkö kattoon. [1] Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). Green Data Centers: A Survey, Perspectives, and Future Directions (arXiv:1608.00687). arXiv.


### Sijaintipäätös sähköisen infrastruktuurin ja energian näkökulmasta (Suomi)

#### Miksi?

Sijaintipäätös kannattaa tehdä sähkö- ja energiavirtojen ehdoilla varhaisessa vaiheessa, koska teho- ja liittymärajoitteet, redundanssivaatimukset sekä energian alkuperä lukitsevat pitkälti sekä investoinnin toteutettavuuden että elinkaaren päästöprofiilin. Vihreän datakeskuksen näkökulmasta sijainti on käytännössä päätös siitä, **mistä sähkö tulee, miten se todennetaan ja millä energiatehokkuudella lämpö poistetaan ja (mahdollisesti) hyödynnetään**. [1][7][9]

Tutkimus- ja asiantuntijatiedon perusteella sijaintiin kytkeytyvät ratkaisevat tekijät voidaan tiivistää neljään kokonaisuuteen (sähkö, sähköntuotannon päästöt/todentaminen, jäähdytysilmasto, hukkalämpö) sekä yhteen reunaehtoon (viive/saatavuus). [1][6][7][9]


#### Mitä tehdään

Käytännöllinen ja läpinäkyvä malli on kaksivaiheinen: **(1) porttikriteerit (go/no-go)** ja **(2) pisteytys ja painotettu vertailu (1–5)**.

**Vaihe 1: Porttikriteerit (go/no-go)**  
Karsi sijainnit, jos jokin näistä ei täyty:

1) **Sähköverkon kapasiteetti ja luotettavuus (liittymäpolku + aikataulu)**  
- varmista liityntämahdollisuus (MW), aikataulu ja kustannusrakenne (liityntä- ja tehomaksut)  
- määritä palvelutasotarpeen mukaan redundanssi (N+1 / 2N) ja tarkista kahden syötön realismi  
- dokumentoi kriittiset epävarmuudet (mitä pitää vielä varmistaa ja keneltä) [7][9]

2) **Sähkön päästöintensiteetti ja uusiutuvan energian todentaminen**  
- valitse hankintamalli: PPA, alkuperätakuut (GoO), oma tuotanto tai portfolio  
- dokumentoi todentaminen ja raportointi (mitä väitetään ja millä todisteella)  
- arvioi, voiko kuormaa ohjata (aikaperusteinen optimointi) palvelutasoa rikkomatta [1][9]

3) **Ilmasto ja vapaajäähdytys (free cooling) – jäähdytyksen edellytykset**  
- laske free cooling -tuntipotentiaali (lämpötila + kosteus) ja tee oletus näkyväksi  
- valitse jäähdytysarkkitehtuuri olosuhteiden mukaan (air-/water-side economizer, hybridi, neste)  
- kirjaa rajoitteet (kosteudenhallinta, kondenssi, käyttörajat) [7][4]

4) **Hukkalämmön hyödyntäminen – vastaanottaja ja integraation realismi**  
- tee vastaanottajakartoitus (kaukolämpö / teollisuus / kiinteistöt)  
- tarkista lämpötaso, tehovaatimus, siirtomatka, liittymiskustannukset ja toteutusmalli (esim. lämpöpumppu)  
- dokumentoi “go/no-go”: onko realistinen vastaanottaja ja miksi [1][7][9]

**Reunaehto: Latenssi ja käyttäjävaatimukset (viive, saatavuus, redundanssi)**  
- varmista, että sijainti täyttää kuorman viive- ja saatavuusvaatimukset  
- huomioi, että kuorman siirto puhtaamman/halvemman energian alueille onnistuu vain, jos palvelutaso sallii sen [6][8]

**Avoimet tietolähteet (pisteytyksen syöttödata)**

Porttivaiheessa varmistetaan toteutettavuus (go/no-go), ja pisteytysvaiheessa verrataan vaihtoehtoja yhtenäisillä mittareilla. Jotta pisteytys on läpinäkyvä ja toistettavissa, suositellaan hyödyntämään ensisijaisesti avoimia tietolähteitä ja viranomais-/järjestelmätoimijoiden julkaisuja.**Avoimet tietolähteet (pisteytyksen syöttödata)**

Porttivaiheessa varmistetaan toteutettavuus (go/no-go), ja pisteytysvaiheessa verrataan vaihtoehtoja yhtenäisillä mittareilla. Jotta pisteytys on läpinäkyvä ja toistettavissa, suositellaan hyödyntämään ensisijaisesti avoimia tietolähteitä ja viranomaisten/järjestelmätoimijoiden julkaisuja:

- **Sähköliittymä ja kantaverkko:** Fingrid (liityntätilanne, pullonkaulat, vahvistushankkeet; Grid Scope)  
  URL: https://www.fingrid.fi/  
  Haettu: 2026-01-05. Saatavuus: avoin (selain).  
  (Avoin data: https://data.fingrid.fi/ — Haettu: 2026-01-05. Saatavuus: avoin (API + selain).)

- **Aurinkopotentiaali:** PVGIS (JRC) – säteily ja PV-tuotto  
  URL: https://joint-research-centre.ec.europa.eu/pvgis_en  
  Haettu: 2026-01-05. Saatavuus: avoin (selain + API).

- **Tuulipotentiaali:** Ilmatieteen laitoksen Tuuliatlas  
  URL: https://tuuliatlas.fi/  
  Haettu: 2026-01-05. Saatavuus: avoin (selain).

- **Free cooling -potentiaali:** Ilmatieteen laitoksen avoin data (lämpötila + kosteus tuntiprofiileina)  
  URL: https://www.ilmatieteenlaitos.fi/avoin-data  
  Haettu: 2026-01-05. Saatavuus: avoin (API + selain).

- **Tulvariskit:** SYKE/Tulvakeskus – tulvakartat ja riskialueet  
  URL: https://www.vesi.fi/aiheet/vesiymparisto-ja-maankaytto/tulvat/  
  Haettu: 2026-01-05. Saatavuus: avoin (selain).

- **Kuitu ja peitto:** Traficom – laajakaistan saatavuus/peitto (täydennä tarvittaessa operaattoriselvityksellä)  
  URL: https://www.traficom.fi/  
  Haettu: 2026-01-05. Saatavuus: avoin (selain; osa aineistoista ladattavissa).

- **Tontti ja kaavoitus:** kunnan kaavat + paikkatietoaineistot (rakennettavuus ja rajoitteet)  
  URL (MML rajapinnat): https://www.maanmittauslaitos.fi/rajapinnat  
  Haettu: 2026-01-05. Saatavuus: avoin/rekisteröityminen voi vaatia tunnistautumista.  
  URL (kunta): [lisää kohdekunnan kaavapalvelun URL]  
  Haettu: 2026-01-05. Saatavuus: vaihtelee kunnittain.



**Vaihe 2: Pisteytys ja painotettu vertailu (1–5)**  
Pisteytä vain portista läpäisseet sijainnit (1 = heikko/korkea riski, 5 = erinomainen/matala riski).  
Esimerkkipainotus: sähkö 35 %, lämpöintegraatio 20 %, jäähdytysilmasto 15 %, kuitu 15 %, vesi+lupitus 15 %.

- kirjaa jokaiselle pisteelle **1 lauseen perustelu**  
- tee vähintään yksi **painotusten vaikutuksen tarkistus**: muuta painoja kohtuullisesti (esim. sähkö 35 % → 45 % ja vähennä muista vastaavasti) ja katso, muuttuuko sijaintien järjestys.  
- nosta päätökseksi 1–2 parasta sijaintia jatkoselvitykseen ja varasuunnitelma (plan B) [7][9]


#### Tuotokset (deliverables)

Minimissään:

- **Sijaintivaihtoehtojen esikarsinta (go/no-go) -muistio**  
  - porttikriteerit täyttyvät / eivät täyty + perustelu + avoimet kysymykset

- **Pisteytystaulukko (1–5) + painotukset + herkkyystarkastelu**  
  - näkyvät oletukset ja perustelut → päätös on läpinäkyvä myös sidosryhmille

- **Sähkö- ja energiadokumentaatio**  
  - liittymäpolku (MW, aikataulu, kustannukset, redundanssi)  
  - uusiutuvan hankintamalli ja todentaminen (PPA/GoO/oma tuotanto)  
  - suunnitelma päästö- ja energiaraportoinnista [1][9]

- **Jäähdytyksen ja hukkalämmön alustava toteutettavuuskuvaus**  
  - free cooling -tuntipotentiaalin laskentaoletus  
  - hukkalämmön vastaanottajakartoitus + integraatiopolku (jos realistinen) [4][7][9]

- **Viive- ja saavutettavuusreunaehdot**  
  - kuormatyypeittäin (latenssiherkkä / ei-latenssiherkkä) hyväksyttävä viive ja redundanssi [6][8]


#### Jos vaihe tehdään huonosti / ohitetaan

- **Sähköliittymän varmistus epäonnistuu**, jos tarvittava kapasiteetti (MW), toteutusaikataulu, kustannusarvio tai vaadittu toimitusvarmuus (esim. kahden syötön toteutettavuus) eivät toteudu oletetusti → seurauksena viiveitä, lisäinvestointeja tai palvelutason heikkenemistä. [7][9] 
- **Vihreät tavoitteet jäävät toiveiksi**: uusiutuvan todentaminen, päästöraportointi tai kuormanohjaus ei toteudu käytännössä, vaikka ne on kirjattu tavoitteiksi. [1][2][9]  
- **Jäähdytys suunnitellaan väärille oletuksille**: free cooling -etu jää realisoitumatta tai kosteudenhallinta aiheuttaa käyttörajoitteita → energiankulutus ja riskit kasvavat. [4][7]  
- **Hukkalämpöpotentiaali menetetään**: vastaanottajaa ei kartoiteta ajoissa → integraatio ei onnistu myöhemmin kohtuukustannuksella. [7][9]  
- **Verkko/latenssi unohtuu**: sijainti rajoittaa palveluiden laatua tai estää kuorman siirron energian mukaan → operointi kallistuu ja “vihreä optimointi” jää vajaaksi. [6][8]


#### Lähteet (viitenumerointi)

[1] Green Data Centers: A Survey, Perspectives, and Future Directions.  
[2] Energy efficiency and low carbon enabler green IT framework for data centers (Uddin & Rahman).  
[3] DATAZERO – Datacenter With Zero Emission and Robust Management Using Renewable Energy.  
[4] Design and Operational Analysis of a Green Data Center (MGHPCC).  
[5] Energy storage techniques, applications, and recent trends – A sustainable solution for power storage.  
[6] The Datacenter as a Computer – An Introduction to the Design of Warehouse-Scale Machines.  
[7] Data Center Handbook (toim. Hwaiyu Geng).  
[8] A Taxonomy and Survey on Green Data Center Networks.  
[9] The ICT sector, climate and the environment – Interim report (LVM 2020:14).


## 3-Vihreän datakeskuksen peruselementit ja periaatteet
Vihreä datakeskus on kokonaisuus, jossa IT-kuorma, sähköketju, jäähdytys, rakennus sekä ohjaus ja valvonta suunnitellaan yhtenä järjestelmänä, ja toimintaa johdetaan sovituilla, mitattavilla energia- ja ympäristötunnusluvuilla. 
Vihreän datakeskuksen ratkaisut jäsentyvät neljään koriin: (1) energiatehokkuus IT:ssä, (2) resurssienhallinta, (3) lämpötilanhallinta ja (4) mittarit & monitorointi [4]. Lisäksi modernissa suunnittelussa korostuu ajatus datakeskuksesta “yhtenä tietokoneena” (warehouse-scale computer), jolloin energiatehokkuus ja käytettävyys syntyvät yhtä paljon ohjelmistosta ja orkestroinnista (automaattisesta kuormien ja resurssien ohjauksesta) kuin laitevalinnoista. [1]

3.1 IT-kerros: energiatehokas laskenta ja resurssienhallinta

Tavoite: tuottaa sama palvelutaso pienemmällä energialla ja vähemmällä ylikapasiteetilla.
-Energiatehokkuus (DVFS ja lepotilat): Prosessorien dynaaminen taajuus-/jännitesäätö (DVFS, eli kellotaajuuden ja käyttöjännitteen automaattinen säätö kuorman mukaan) sekä lepotilat/power-down-tilat (eli käyttämättömien ytimien, komponenttien tai jopa koko palvelimen siirtäminen matalatehotilaan) ovat keskeisiä keinoja tehdä kulutuksesta kuormaa vastaavaa (“energy-proportional”). [4]

-Virtualisointi ja konsolidointi: Virtualisointi tarkoittaa, että samalla fyysisellä palvelimella voidaan ajaa useita erillisiä “virtuaalisia palvelimia” (virtuaalikoneita tai kontteja), jolloin sovellukset eivät ole sidottuja yhteen laitteeseen. Konsolidointi tarkoittaa, että nämä kuormat kootaan tarkoituksella harvemmille fyysisille palvelimille niin, että käyttöaste nousee. Kun kuormat ajetaan korkeammalla käyttöasteella harvemmilla palvelimilla, säästyy sekä IT-sähköä että jäähdytystä; samalla voidaan sammuttaa vajaakäytöllä olevia laitteita hallitusti. Tämä kuuluu resurssienhallinnan ytimeen. [4]

-Tehorajoitus (power capping) ja kuormien ohjaus: IT-kuormaa voidaan rajoittaa ja siirtää ajallisesti/paikallisesti sähkön hinnan, uusiutuvan saatavuuden tai lämpötilatilanteen mukaan (orkestrointi + kapasiteettipolitiikat). [4]

3.2 Sähkö: syötöt, UPS, varavoima, jakelu ja häviöiden minimointi

Tavoite: saavuttaa korkea käytettävyys mahdollisimman pienin häviöin ja mitoittaa sähkönsyöttö- ja jakelujärjestelmä kuormitusprofiilin mukaisesti (välttäen “varmuuden vuoksi” -ylimitotusta), siten että ratkaisu tukee asetettuja ympäristötavoitteita.

-Sähkönsyöttö- ja jakeluketjun hyötysuhde. Green IT -viitekehykset korostavat koko sähkönsyöttöketjun häviöiden systemaattista mittaamista ja pienentämistä muuntajilta (jännitetasomuunnokset) UPS-laitteiston kautta PDU-yksiköihin (Power Distribution Unit; sähkönjakeluyksikkö/räkkijakelu) ja lopulta IT-kuormalle (palvelimet, verkko ja tallennus). Tavoitteena on mittaripohjainen johtaminen, jossa häviöt tehdään näkyväksi ja niiden kehitystä seurataan ajassa. [7]

-Varmistusratkaisut vs. energiatehokkuus: Koska N+1- ja 2N-varmistus lisää usein osakuormalla käyviä laitteita ja siten häviöitä. Tämä kasvattaa häviöitä erityisesti silloin, kun järjestelmän kuormitusaste on pitkäkestoisesti matala.  Vaikutus tulee tehdä näkyväksi mittareilla ja kuormaprofiileilla,jotta varmistuksen ja energiatehokkuuden välinen kompromissi voidaan käsitellä eksplisiittisesti. Vihreä toteutus tarkoittaa varmistuksen ja energiatehokkuuden yhteisoptimointia sekä suunnittelussa että operoinnissa [6] . 

-Energiavarastointi ja UPS osana datakeskuksen energianhallintaa. Energiavarastointi (esim. akkuvarasto/BESS) ja UPS (Uninterruptible Power Supply; keskeytymätön virransyöttö) ovat datakeskuksen energianhallinnan ja sähkönsyötön jatkuvuuden keskeisiä toteutuskomponentteja. Energiavarastolla voidaan toteuttaa tehon- ja kuormituksenhallintaa (peak shaving), tukea datakeskuksen paikallisen sähkönjakelun toimintaa (UPS, varavoima ja mahdollinen energiavarasto) sekä parantaa uusiutuvan energian hyödyntämistä ajallisen siirron kautta (ylijäämän varastointi ja myöhempi käyttö) [8].

-Mitoitus ja häviöt: “vihreys” syntyy käyttöprofiilissa. Ympäristötehokkuus alkaa mitoituksesta ja kuormitusprofiilista: sekä UPS- että varastojärjestelmien järjestelmätason hyötysuhde ja omakulutus muodostuvat muunnosketjun häviöistä (tehoelektroniikka, lataus/purkaus) sekä kuormasta riippumattomista perushäviöistä (ohjaus, valvonta, suojaukset ja mahdollinen lämpöhallinta). Ylimitoitus kasvattaa pitkäkestoisen osakuormakäytön todennäköisyyttä, jolloin perushäviöiden suhteellinen osuus kasvaa ja nettotehokkuus heikkenee; samalla myös poistettavan hukkalämmön määrä voi kasvaa. Tämän vuoksi vihreässä suunnittelussa korostuvat kuormitusdataan perustuva mitoitus (tai modulaarinen kapasiteetti) sekä häviöiden minimointi koko suunnitellulla käyttöalueella. [11] [15]

-Energianvarastointitekniikan valinta käyttötarpeen mukaan. Energiavarastointitekniikka valitaan vaaditun keston ja vasteajan perusteella. Lyhyisiin katkottomuustarpeisiin (sekunnit–minuutit) soveltuvat mm. vauhtipyöräratkaisut, joiden vasteaika on millisekuntitasoa ja tyypillinen purku-/latauskesto 20 s–20 min; ominaisuuksiltaan ne sijoittuvat superkondensaattorien ja akkujen väliin. [12] Esimerkiksi MGHPCC-konesalissa (Massachusetts Green High Performance Computing Center) käytetään vauhtipyöräpohjaista UPS:ää generaattorien käynnistymiseen asti, ja ratkaisun yhteydessä korostetaan myös kompromissia: vauhtipyörän valmiustila kuluttaa energiaa, joten varmistus voidaan rajata vain osaan kuormasta energiatehokkuuden ja käytettävyyden tasapainottamiseksi. [6].

Tuntien mittakaavan varakesto ja energian ajallinen siirto. Jos tavoitteena on pidempi varakesto tai energian ajallinen siirto (tuntien mittakaavassa), akkuvarasto on tyypillinen vaihtoehto. Litiumioni-BESS (Battery Energy Storage System) koostuu akustosta sekä ohjaus- ja suojajärjestelmistä ja tehoelektroniikasta, joiden avulla energiaa voidaan varastoida ja syöttää takaisin kuormalle tai sähköverkkoon; tyypillinen purkukesto on usein 1–6 tuntia. Superkondensaattorit soveltuvat puolestaan erityisesti lyhytkestoiseen UPS- ja power quality -tukeen suurille hetkellisille kuormille. [13]

Elinkaariperustelu. “Vihreys” kannattaa perustella myös elinkaarella: elinkaariarvioinneissa litiumioniakkujen ympäristövaikutusten on raportoitu olevan useissa tarkastelluissa vaikutusluokissa pienemmät kuin lyijyakkujen (per toimitettu kWh). Samalla korostuu käyttö­vaiheen sähkön merkitys: lataussähkön päästöintensiteetti (millä sähköllä varasto käytännössä ladataan) vaikuttaa kokonaisvaikutukseen olennaisesti. [14]


3.3 Jäähdytys ja lämpötilanhallinta: ilma, neste, free cooling ja “kuuma–kylmä”

Tavoite: poistaa lämpö mahdollisimman pienellä jäähdytyssähköllä ja hallita luotettavuus–lämpötila-kompromissi.

-Free cooling ja ilmavirtojen hallinta: Pitkä vapaajäähdytyskausi on käytännössä Suomen vakioetu, mutta hyödyt realisoituvat vasta, kun ilmavirrat (kuuma/kylmä-käytävä, tiiveys, ohivirtausten estäminen) ja ohjauslogiikka ovat kunnossa. Lämpötilanhallinta on tutkimuskoosteissa oma pääluokkansa juuri siksi, että se kytkeytyy sekä IT-kuorman sijoitteluun että rakennusratkaisuihin. [4]

-Nestejäähdytys ja immersion (immersiojäähdytys): Nestejäähdytys tarkoittaa, että lämpö siirretään ilmasta nesteeseen lähellä lämmönlähdettä (esim. “direct-to-chip”), jolloin puhaltimien ja ilman kierron tarve pienenee. Immersiojäähdytys on nestejäähdytyksen alalaji, jossa palvelin(komponentit) upotetaan sähköä johtamattomaan nesteeseen. Oppaassa tämä kannattaa esittää valintana erityisesti, kun tehotiheys on korkea tai hukkalämmön hyödyntämiselle halutaan korkeampi lämpötila (helpompi lämmöntalteenotto). (Tämä kohta on tekninen periaatekuvaus; perustele omilla kohdevaatimuksilla ja toimittajadokumenteilla.)

-Käytännön esimerkki “green”-suunnittelusta: MGHPCC-tapaustutkimus kuvaa nimenomaan suunnittelun ja operoinnin yhteisvaikutusta energiatehokkuuteen ja antaa uskottavan referenssikehyksen (mitä mitataan, mitä optimoidaan, miten operointikäytännöt vaikuttavat). [6]

3.4 Rakennus: ilmavirrat, tiiveys, modulaarisuus ja huollettavuus

Tavoite: mahdollistaa energiatehokas jäähdytys ja turvallinen ylläpito koko elinkaaren ajan.

-Datakeskuksen “shell” ja MEP-ratkaisut (sähkö + jäähdytys + tilat) tulee kuvata selkeästi perusoppaassa: tilajaot, huoltotilat, kaapelireitit, tiiveysratkaisut, skaalautuvuus. Data Center Handbook toimii hyvänä runko-ohjeena, koska se jäsentää datakeskuksen suunnittelun rakennuksesta sähköön ja jäähdytykseen sekä operointiin. [3]

-Kun yhdistät tämän “datacenter-as-a-computer” -ajatteluun, saat perustelun sille, miksi rakennus ei ole vain kustannuserä vaan osa suorituskykyä, energiatehokkuutta ja käytettävyyttä. [1]

3.5 Mittarit ja valvonta: PUE, CUE ja jatkuva optimointi

Tavoite: tehdä vihreys todennettavaksi ja ohjattavaksi.
-Tutkimuksissa mittarit ja monitorointi ovat oma pääpilarinsa: ilman jatkuvaa mittausta (IT-kuorma, jäähdytys, sähköketjun häviöt, lämpötilat, uusiutuvan osuus) “vihreys” jää väitteeksi. [4]

-Oppaaseen kannattaa kirjata vähintään: PUE (kokonaisenergiatehokkuus), CUE (hiili-intensiteetti), sekä käytännön mittauspisteet (mistä PUE lasketaan, mitä mitataan PDU/UPS-tasolla ja jäähdytyksessä). [7]

3.6 Verkko (DCN): energiatehokas liikenne ja verkko-tietoinen sijoittelu

Tavoite: välttää tilanne, jossa “vihreä IT ja jäähdytys” tehdään, mutta verkko syö hyödyt.
-Vihreän datakeskuksen verkko ei ole vain kapasiteettikysymys: tutkimuskoosteet nostavat esiin energiatehokkaat topologiat, linkkien/porttien dynaamisen ohjauksen sekä verkko-tietoisen kuormien sijoittelun. [2]

3.7 Uusiutuva integraatio ja mikroverkot (valinnainen moduuli)

Tavoite: nostaa uusiutuvan osuutta ja parantaa hallittavuutta.
-DATAZERO-tyyppiset ratkaisut kokoavat datakeskuksen osaksi mikroverkkoa (tuuli/aurinko/verkko + varastointi), jolloin kuorman, varaston ja tuotannon ohjaus linkittyy yhteen. Tämä sopii oppaaseen “edistyneet ratkaisut” -laatikoksi (milloin kannattaa, mitä edellyttää). [9]

| Ratkaisu                                        | Sopii erityisesti kun…                                                                                                     | Ei ensisijainen kun…                                                                                    |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Perinteinen ilmajäähdytys + hot/cold aisle      | tehotiheydet maltillisia, investointibudjetti tiukka, halutaan yksinkertainen operointi                                    | erittäin korkeat tehotiheydet, tavoitteena korkea lämpötila hukkalämmölle                               |
| Free cooling (ilma-/vesipuoli)                  | sijainti tarjoaa pitkän viileän kauden (Suomi), halutaan pieni jäähdytyksen ostoenergia                                    | ilmanlaatu/olosuhteet rajoittavat, tai prosessi vaatii tarkkaa kosteushallintaa ilman lisäratkaisuja    |
| Direct-to-chip nestejäähdytys                   | tehotiheys kasvaa, halutaan pienempi puhallinsähkö ja parempi lämmön talteenotto                                           | organisaatiolla ei ole valmiutta neste-infraan ja huoltoprosesseihin                                    |
| Immersiojäähdytys                               | erittäin korkea tehotiheys, halutaan maksimoida jäähdytyksen hyötysuhde ja/tai nostaa lämpötilatasoa lämmön hyödyntämiseen | tarvitaan laajaa laiteyhteensopivuutta vakiohardwarella tai operointi ei siedä muutosta huoltomalleihin |
| Energiavarasto (UPS/akku laajempaan ohjaukseen) | uusiutuvan osuus suuri, halutaan peak-shaving / jousto / varmistus yhdestä arkkitehtuurista                                | kuorma pieni ja verkko erittäin vakaa eikä joustosta saada arvoa                                        |
| Modulaarinen laajennus (hallittava kasvu)       | kuorma kasvaa vaiheittain, halutaan välttää ylikapasiteetti                                                                | kuorma on heti suuri ja vakaa, ja kerralla rakentaminen on tehokkainta                                  |

Lähteet (APA 7)

[1] Barroso, L. A., Hölzle, U., & Ranganathan, P. (2022). The Datacenter as a Computer: Designing Warehouse-Scale Machines (3rd ed.). Springer Cham. https://doi.org/10.1007/978-3-031-01761-2

[2] Bilal, K., Malik, S. U. R., Khalid, O., Hameed, A., Alvarez, E., Wijaysekara, V., Irfan, R., Shrestha, S., Dwivedy, D., Ali, M., Shahid Khan, U., Abbas, A., Jalil, N., & Khan, S. U. (2014). A taxonomy and survey on Green Data Center Networks. Future Generation Computer Systems, 36, 189–208. https://doi.org/10.1016/j.future.2013.07.006

[3] Geng, H. (Ed.). (2021). Data Center Handbook: Plan, Design, Build, and Operations of a Smart Data Center (2nd ed.). Wiley.

[4] Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). Green Data Centers: A Survey, Perspectives, and Future Directions (arXiv:1608.00687). arXiv. https://arxiv.org/abs/1608.00687

[5] Ministry of Transport and Communications (Finland). (2020). The ICT sector, climate and the environment: Interim report of the working group preparing a climate and environmental strategy for the ICT sector in Finland. (Publications of the Ministry of Transport and Communications).

[6] Sharma, P., Pegus II, P., Irwin, D. E., Shenoy, P. J., Goodhue, J., & Culbert, J. (2017). Design and operational analysis of a green data center. IEEE Internet Computing, 21(4), 16–24.

[7] Uddin, M., & Rahman, A. A. (2012). Energy efficiency and low carbon enabler green IT framework for data centers considering green metrics. Renewable and Sustainable Energy Reviews, 16(6), 4078–4094. https://doi.org/10.1016/j.rser.2012.03.014

[8] Vaghela, P., Pandey, V., Sircar, A., Yadav, K., Bist, N., & Kumari, R. (2023). Energy storage techniques, applications, and recent trends: A sustainable solution for power storage. MRS Energy & Sustainability, 10, 261–276. https://doi.org/10.1557/s43581-023-00069-9

[9] ANR (Agence Nationale de la Recherche). (n.d.). DATAZERO – Datacenter With Zero Emission and Robust Management Using Renewable Energy (ANR-15-CE25-0012).

Uudet (lisätty loppuun):

[10] International Energy Agency – Energy Storage Technology Collaboration Programme (IEA-ES). (2024, September). Technology: Flywheel Energy Storage [Fact sheet]. https://www.iea-es.org/wp-content/uploads/public/FactSheet_mechanical_flywheel.pdf 
IEA ES TCP

[11] Gagne, D. (2024, March 26). Energy Storage (NREL/PR-7A40-89172) [Presentation slides]. National Renewable Energy Laboratory. https://docs.nrel.gov/docs/fy24osti/89172.pdf 
docs.nrel.gov

[12] U.S. Environmental Protection Agency. (2017). ENERGY STAR® program requirements: Product specification for uninterruptible power supplies (UPSs)—Eligibility criteria (Version 2.0, Rev. Dec-2017). ENERGY STAR. https://www.energystar.gov/sites/default/files/ENERGY%20STAR%20Uninterruptible%20Power%20Supplies%20Final%20Version%202.0%20Specification_2.pdf 
ENERGY STAR

[13] Yudhistira, R., Khatiwada, D., & Sanchez, F. (2022). A comparative life cycle assessment of lithium-ion and lead-acid batteries for grid energy storage. Journal of Cleaner Production, 358, 131999. https://doi.org/10.1016/j.jclepro.2022.131999 sciencedirect.com

[15] U.S. Environmental Protection Agency. (n.d.). Reduce energy loss from uninterruptible power supply systems. ENERGY STAR. Retrieved December 22, 2025, from https://www.energystar.gov/products/data_center_equipment/16-more-ways-cut-energy-waste-data-center/reduce-energy-losses-uninterruptible-power-supply-ups-systems


# 4. Datakeskuksen elinkaaren vaiheet

# Datakeskuksen elinkaaren vaiheet (syvennetty Green ICT -näkökulmalla)

Tämä osio kokoaa vihreän datakeskuksen elinkaaren vaiheet ja avaa, mitä kullakin vaiheella tarkoitetaan, miksi se on kriittinen energiatehokkuuden, ympäristövastuun ja kustannusten hallinnan kannalta – sekä mitä seuraa, jos vaihe jää vajaaksi. Elinkaaren logiikka on “ketju”: jokainen vaihe tuottaa dokumentteja ja päätöksiä, joita seuraava vaihe käyttää lähtötietoina. Elinkaariketjun suurin riski on se, että tehdään päätöksiä ilman riittävää dataa ja dokumentaatiota, jolloin virheet näkyvät vasta myöhemmin – silloin korjaus on kallista ja hidasta. [1][3][4]


## Yleiskuva elinkaaresta ja riippuvuuksista

| Vaihe | Tavoite | Keskeinen kysymys | Mitä tuotetaan seuraavalle vaiheelle |
|---|---|---|---|
| Tarvekartoitus ja esiselvitys | Oikea tarve, oikea koko, oikea sijainti | “Miksi ja minkä kokoinen?” | Vaatimusmäärittely + vihreät KPI:t + vaihtoehtopäätökset |
| Suunnittelu | Muuttaa vaatimukset toteutuskelpoiseksi | “Miten toteutetaan mitattavasti vihreänä?” | Basis of Design, piirustukset, mittaussuunnitelma, hankinnat |
| Päätöksenteko ja luvitus | Luvallisuus + investointilukitus | “Saammeko rakentaa ja kannattaako?” | Lupahakemukset, vaikutusarviot, stage-gate-päätökset |
| Rakentaminen | Rakennetaan suunnitelmien mukaan | “Rakennammeko oikein ja mitattavasti?” | As-built, testiraportit, käyttöönotto-valmius |
| Käyttöönotto, käyttö ja modernisointi | Todennetaan suorituskyky, optimoidaan | “Miten pidämme tehokkaana koko elinkaaren?” | Baseline, jatkuva optimointi, muutoshallinta |
| Käytöstäpoisto ja uudelleenkäyttö | Turvallinen purku + kiertotalous | “Miten minimoimme elinkaaren loppupään vaikutukset?” | Sanitointi, kierrätys, opit seuraavaan hankkeeseen |

Seuraavissa kappaleissa avataan kunkin vaiheen keskeiset toimet ja vihreät huomionaiheet.


## 4.1) Tarvekartoitus ja esiselvitys

### Miksi?
Tässä vaiheessa päätetään 70–80 % myöhemmistä kustannus- ja energiatehokkuusominaisuuksista, koska valitaan kuormaprofiili, palvelutasot, sijainti ja tavoitearkkitehtuuri. Väärä mitoitus näkyy joko ylikapasiteettina (pysyvät perushäviöt, turha infra) tai alikapasiteettina (SLA/SLO-riski, kiireiset laajennukset). [1][2][3]

### Mitä tehdään (sisältö, ei vain lista)?
- **Kuorman ja palvelutason määrittely:** erottele IT-kuorma, jäähdytyskuorma ja infrastruktuurikuorma; määritä kuormaprofiili (päivä/viikko/kausi) eikä vain “maksimikilowatit”. [3][13]  
- **Sijainnin arviointi (Suomi):** vapaajäähdytyskausi, sähkön saatavuus ja liityntäkapasiteetti, kuituyhteydet, hukkalämmön hyödyntäminen (kaukolämpöverkko / prosessilämpö), sekä maankäyttö ja lupaympäristö. [3][11]  
- **Ratkaisuvaihtoehdot:** oma / colocation / pilvi / hybridi – vertaile todellista ohjattavuutta (mittaus, energialähteet, hukkalämpö) ja vastuujakoa (kuka vastaa mittareista ja raportoinnista). [1][2][3]  
- **Vihreät tavoitteet ja mittarit:** aseta KPI:t (PUE, WUE, CUE, uusiutuvan osuus, hukkalämmön hyödyntämisaste) ja tee niistä projektin “sopimus”: niitä vasten hyväksytään suunnitelmat ja käyttöönotto. [2][3][11]  

### Tuotokset (deliverables)
Minimissään:
- **Vaatimusmäärittely (Requirements):** kapasiteetti, SLA/SLO, redundanssitaso, laajennuspolku, IT-arkkitehtuuriperiaatteet. [1][3]  
- **Vihreä tavoitekehys:** KPI-tavoitteet + mittausperiaatteet + raportointitarpeet (myös EU-tasolle). [2][5][6][7]  
- **Feasibility + TCO/LCA-suunta:** kustannus- ja ympäristövaikutusten suunta-arvio vaihtoehdoille. [2][17]  

### Jos vaihe ohitetaan / tehdään heikosti
- Koko hanke voi “lukittua” väärään kokoon → myöhemmin rakennetaan kiireessä lisää (kalliimpaa, epäoptimoitua) tai pyöritetään vajaakuormalla (häviöt).  
- KPI:t jäävät “toiveiksi” → suunnittelussa ei ole tarkkaa mittaus- ja todentamispolkua, jolloin käyttöönotossa ei tiedetä, saavutettiinko vihreys oikeasti. [2][3]  


## 4.2) Suunnittelu

### Miksi?
Suunnittelussa päätetään, miten vihreys toteutuu konkreettisina teknisinä ratkaisuina ja ennen kaikkea mitattavuutena (measurement & verification). Tämä vaihe tuottaa rakennusvaiheen “ohjekirjan”: jos dokumentaatio on puutteellinen, rakennusvaiheessa tehdään tulkintoja – ja tulkinnat maksavat. [1][3][4]

### Mitä tehdään 

#### A) Mittauspisteet ja todentaminen (M&V)
- Määritä PUE/WUE/CUE-laskennan rajat: mikä lasketaan “IT load” vs “facility load”; missä kohtaa mitataan sähkö (pääkeskus, UPS-lähtö, PDU/rack). [3][13]  
- Määritä sensorien tarkkuusluokat, aikaleimavaatimukset ja data-ketju (BMS/DCIM), jotta mittausdata kelpaa päätöksentekoon ja raportointiin. [3][6][7]  
---

**Liite A:** Mittauspisteiden minimirunko (konkreettinen mittaripistekartta).


#### B) Automaatiot ja rajapinnat
- Suunnittele ohjauslogiikat (jäähdytys, ilmanvaihto, pumput, varavoima) ja aseta ohjaukselle tavoitteet: minimi häviöt, raja-arvot, hälytykset, “safe mode”. [3][4]  
- Rajaa vastuut: BMS vs DCIM vs IT-orkestrointi. Liian “siiloutunut” ohjaus johtaa paikallisiin optimointeihin, jotka heikentävät kokonaisuutta.  

#### C) Modulaarisuus ja kasvumahdollisuudet
- Suunnittele kapasiteetin kasvatus moduuleina (sähkö, jäähdytys, IT-salit). Tavoite: laajennus ilman, että joudutaan remontoimaan kriittisiä runkoratkaisuja. [1][3]  
- **Kestävä modulaarinen suunnittelu:** pitkä käyttöikä, kierrätettävyys ja tehdasvalmistus (laatu, vähemmän työmaajätettä). Suomessa tämä tukee myös nopeaa käyttöönottoa ja vaiheittaista investointia. [18][19]  

#### D) Tekniset ratkaisut (sähkö + jäähdytys + varmistus)
- Valitse redundanssitaso (N+1, 2N) ja arvioi sen energiahinta: ylivarmistus kasvattaa osakuormaa ja häviöitä – tee kompromissi näkyväksi mittareilla ja kuormaprofiililla. [3][4][11]  
- Jäähdytyksen osalta Suomessa vapaajäähdytys on usein vahva lähtökohta, mutta sen hyödyt tulevat vain, jos ilmavirrat/tiiveys/ohjaus ovat kunnossa (tämä on suunnittelussa “lukittava”). [3][4][11]  

### Tuotokset (deliverables) – rakennusvaihe käyttää näitä
- **Basis of Design (BoD):** miksi kukin ratkaisu on valittu (vihreys + riskit + ylläpito). [1][3][4]  
- **Piirustukset ja kaaviot:** sähkö single-line, jäähdytyksen prosessikaaviot, layout (kuuma–kylmä), sensorikartta. [3][4]  
- **Hankintaspesifikaatiot:** laitevaatimukset (hyötysuhde, ohjausrajapinnat, mittausvalmius, huollettavuus). [3][4]  
- **Commissioning-suunnitelma:** miten testataan (myös osakuormilla) ja miten baseline muodostetaan. [3][12]  

### Jos vaihe ohitetaan / tehdään heikosti (tämä on se “kallis boomerangi”)
- Rakentaminen tehdään suunnittelun dokumenteilla. Jos dokumentit ovat vajaita, rakennusvaihe tekee oletuksia → syntyy toteutus, joka ei vastaa KPI-tavoitteita tai jota ei voi kunnolla mitata.  
- Rakennusvaiheessa löytyvä muutos tarkoittaa takaisinkytkentää suunnitteluun:  
  - piirustuksia ja laskelmia päivitetään  
  - laitespesit muuttuvat  
  - jo tilatut laitteet/materialit voivat mennä vaihtoon  
  - tulee palautus- ja uudelleentilauskierroksia (toimitusajat!)  
  - ja aikataulu sekä kustannusarviot venyvät  
  Tämä on tyypillisin syy “vihreys jäi tavoitteeksi” -lopputulokseen. [1][3]  


## 4.3) Päätöksenteko ja luvitus

### Miksi?
Ilman lupia ei rakenneta – ja ilman sääntelyyn sopivaa mittaamista/raportointia projekti voi myöhemmin törmätä vaatimuksiin, joita ei ole huomioitu. EU-tason energiatehokkuus ja datakeskusten luokitus/raportointi korostaa dokumentoitavuutta. [5][6][7][9][10]

### Mitä tehdään
- **Sääntelykartoitus:** energiatehokkuus, raportointi, mahdollinen IED-kehikko, BAT/BREF-vertailu. [5][9][10]  
- **Lupaprosessi (Suomi):** ympäristölupa (AVI) tapauskohtaisesti, rakennuslupa kunnasta, mahdollinen YVA-tarveharkinta; liityntäselvitykset (sähkö/vesi/viestintä). [8][9]  
- **Stage-gate:** portit ja kriteerit (vaatimukset, KPI:t, luvitusvalmius, investointipäätös). [5][6][7]  

### Tuotokset
- Lupahakemukset + liitteet (vaikutusarviot, mittaussuunnitelma, energiatehokkuus- ja raportointisuunnitelma). [5][6][8][9]  

### Jos vaihe ohitetaan / tehdään heikosti
- Luvat viivästyvät → rakentaminen seisoo.  
- Raportointivelvoite huomataan myöhään → joudutaan lisäämään mittauspisteitä jälkikäteen (kallis ja häiritsee käyttöä). [6][7]  


## 4.4) Rakentaminen

### Miksi?
Rakentamisessa “vihreä suunnitelma” muuttuu todellisuudeksi. Tyypillisin energiatehokkuuden epäonnistuminen syntyy siitä, että asennus ja käyttöönotto eivät vastaa suunnittelun oletuksia (mittarit, ilmavirrat, ohjauslogiikat). [3][4][12]

### Mitä tehdään
- **QA/QC mittaroinnille:** asennus, kalibrointi ja signaalitiet (ei vain “asennettu”, vaan “tuottaa oikeaa dataa”). [3]  
- **Jäähdytyksen toteutus:** tiiveys, ohivirtausten estäminen, kuuma–kylmä, ohjauslogiikat. [3][4][11]  
- **Integraatiot:** BMS/DCIM/IT-rajapinnat testataan oikeilla datapoluilla. [3]  
- **As-built:** päivitetään “todellinen toteuma” – tämä on operoinnin perusta. [3][12]  

### Tuotokset
- As-built-dokumentit + testiraportit + kalibrointiraportit. [3][12]  

### Jos vaihe ohitetaan / tehdään heikosti
- Et pysty todentamaan PUE/WUE/CUE luotettavasti → optimointi ja raportointi kärsii.  
- “Pienet” asennusvirheet (sensoripaikka, tiiveys) → jatkuva energiahukka koko elinkaaren ajan.  


## 4.5) Käyttöönotto, käyttö ja modernisointi

### Miksi?
Vihreä datakeskus ei ole “rakennettu ja valmis”, vaan operoinnissa optimoitava järjestelmä. Lisäksi IT-kuorma muuttuu: ilman jatkuvaa seurantaa ja modernisointia energiatehokkuus valuu pois. [3][11][12][13]

### Mitä tehdään
- **Baseline-testit:** eri kuormatasot, PUE/WUE-baseline, toiminnalliset testit. [3]  
- **Jatkuva seuranta:** hälytysrajat, trendit, poikkeamat, jatkuva commissioning. [3][12]  
- **Modernisointi:** laite- ja ohjauspäivitykset, kapasiteetin lisäys moduuleina, vaikutusten mittaus ennen/jälkeen. [3][11][12]  

### Tuotokset
- Baseline + jatkuvan optimoinnin prosessit + muutoshallintadokumentit.

### Jos vaihe ohitetaan / tehdään heikosti
- Energiatehokkuus heikkenee “hiljaa” (setpoint drift, ohivirtaus, osakuormat).  
- Laajennukset tehdään ilman vaikutusmittausta → uusi kapasiteetti tuo suhteettomasti häviöitä.  


## 4.6) Käytöstäpoisto ja uudelleenkäyttö

### Miksi?
Elinkaaren loppu vaikuttaa sekä ympäristöön että tietoturvaan. Vihreys ei ole uskottavaa, jos purku ja e-jäte hoidetaan huonosti. [14][15][16][17]

### Mitä tehdään
- **Media sanitization:** NIST 800-88 mukaiset menetelmät. [14]  
- **Uudelleenkäyttö ja kierrätys:** kuntoarvio, materiaalivirrat, vaaralliset jätteet (akut). [15][16]  
- **Oppien keruu:** mikä toimi, mikä ei → syöttö seuraavaan hankkeeseen. [17]  

### Jos vaihe ohitetaan / tehdään heikosti
- Tietoturvariski + mainehaitta.  
- E-jäte menee väärään kanavaan → vastuullisuus- ja compliance-riski.  


## Tiivis “vihreän onnistumisen” sääntö

- Määritä KPI:t ja mittausrajat esiselvityksessä → ne ohjaavat kaikkea. [2][3]  
- Suunnittelussa tee dokumenteista rakennusvaiheen “totuus” (BoD, mittaussuunnitelma, commissioning). [1][3]  
- Rakentamisessa varmista toteuma + as-built + testaus, muuten operointi on sokkona. [3][12]  
- Operoinnissa optimoi jatkuvasti, muuten vihreys rapautuu. [3][11][12]  


## Lähteet

[1] Schneider Electric – Data Center Science Center. (2015). *Fundamentals of Managing the Data Center Life Cycle for Owners* (White Paper).

[2] UNEP DTU Partnership. (2020). *Environmental sustainability of data centres: A need for a multi-impact and life-cycle approach*.

[3] Lawrence Berkeley National Laboratory. (2025). *Best Practices Guide for Energy-Efficient Data Center Design*.

[4] Geng, H. (Ed.). (2014). *Data Center Handbook*. John Wiley & Sons.

[5] Directive (EU) 2023/1791 of the European Parliament and of the Council of 13 September 2023 on energy efficiency (recast). *Official Journal of the European Union*.

[6] Commission Delegated Regulation (EU) 2024/1364 of 14 March 2024 on the first phase of the establishment of a common Union rating scheme for data centres. *Official Journal of the European Union*.

[7] Finnish Energy Authority (Energiavirasto). (2024). *Reporting from data centres to the European database has started*.

[8] Suomi.fi. (n.d.). *Environmental permit – Regional State Administrative Agency*.

[9] Directive 2010/75/EU of the European Parliament and of the Council of 24 November 2010 on industrial emissions (integrated pollution prevention and control). *Official Journal of the European Union*.

[10] European Commission Joint Research Centre. (n.d.). *Best Available Techniques (BAT) Reference Documents (BREFs)*.

[11] Oró, E., Depoorter, V., Garcia, A., & Salom, J. (2015). Energy efficiency and renewable energy integration in data centres: Strategies and modelling review. *Renewable and Sustainable Energy Reviews, 42*, 429–445. https://doi.org/10.1016/j.rser.2014.10.058

[12] Sharma, P., Pegus II, P., Irwin, D. E., Shenoy, P., Goodhue, J., & Culbert, J. (2017). Design and operational analysis of a green data center. *IEEE Internet Computing, 21*(4), 16–24.

[13] Shehabi, A., Smith, S., Sartor, D., Brown, R., Herrlin, M., Koomey, J., Masanet, E., Horner, N., Azevedo, I. L., & Lintner, W. (2016). *United States Data Center Energy Usage Report*. Lawrence Berkeley National Laboratory.

[14] National Institute of Standards and Technology. (2014). *Guidelines for Media Sanitization* (NIST Special Publication 800-88 Rev. 1). U.S. Department of Commerce.

[15] Baldé, C. P., Forti, V., Gray, V., Kuehr, R., & Stegmann, P. (2017). *The Global E-waste Monitor 2017: Quantities, Flows, and Resources*. United Nations University (UNU), International Telecommunication Union (ITU), International Solid Waste Association (ISWA).

[16] Li, J., Zeng, X., Chen, M., Ogunseitan, O. A., & Stevels, A. (2015). Control-Alt-Delete: Rebooting solutions for the e-waste problem. *Environmental Science & Technology, 49*(12), 7095–7102. https://doi.org/10.1021/es5053009

[17] Whitehead, B., Andrews, D., & Shah, A. (2015). The life cycle assessment of a UK data centre. *The International Journal of Life Cycle Assessment, 20*, 332–349. https://doi.org/10.1007/s11367-014-0838-7

[18] Schneider Electric. (2021). *How Modular Data Centers Help Companies Meet Sustainability Goals*.

[19] Datacenter Dynamics. (2023). *Embracing the future: Modularization, sustainability, and efficiency in data centers*.


## 5. Datakeskuksen toiminta vaiheittain – sähköstä palveluksi ja takaisin lämpönä

Tässä luvussa kuvataan datakeskuksen toiminta ketjuna, jossa sähkö ja palvelupyynnöt kytkeytyvät IT-laitteisiin, jäähdytykseen ja syntyvään lämpöön. Kuvauksen tavoitteena on tehdä näkyväksi, miten sähkö muuttuu IT-palveluksi ja käytännössä lämmöksi, miten hukkalämpö voidaan liittää osaksi toimitusketjua sekä miten mittaus tukee ohjausta ja raportointia. [1–4][6–9]

Rakenteena käytetään kolmen vaiheen mallia (sähkönsyöttö ja jäähdytys → verkkopalvelupyynnöt → palvelimet ja lämmöntuotanto) ja täydennetään sitä hukkalämmön hyödyntämisellä sekä mittauksen ja jatkuvan parantamisen toimintamallilla. [1–4][6–9]


### 5.1 Vaihe 1: Sähkönsyöttö ja jäähdytys

#### 5.1.1 Sähkönsyöttö ja virranjakelu (verkosta IT-kuormaan)

Datakeskuksen sähköjärjestelmä muodostuu ketjusta (verkko → muuntajat → UPS → jakelu/PDU → räkit), jossa sekä käytettävyys että häviöt vaikuttavat kokonaiskulutukseen ja jäähdytyskuormaan. Sähköketjun toiminnallinen kuvaus ja tyypilliset arkkitehtuurit esitetään datakeskuksen suunnittelua käsittelevässä kirjallisuudessa. [6][7]

Suomen toimintaympäristössä energian alkuperän ja päästöjen todentaminen sekä raportointi kytkeytyvät käytännön sopimuksiin ja tiedon saatavuuteen. [9] Tämän vuoksi sähköketjun suunnittelun rinnalla määritetään mittaus siten, että IT-kuorma ja infrastruktuurikuorma voidaan erottaa ja raportoida. [2][6][7]

> **Tuotokset**
> - Sähköketjun arkkitehtuuri ja varmistusratkaisut (esim. single line diagram, varmistusluokka, UPS- ja generaattoriperiaate). [6][7]  
> - Mittauspistekartta: kokonaiskulutus (grid-in), UPS sisään/ulos (UPS-häviöt), jakelutasot (esim. PDU/räkki tai ryhmät). [2][6][7]  
> - Raportointiperusteet energian alkuperälle ja päästöille (todentaminen ja laskentaperiaate). [9]
>
> **Mistä saat tämän?**
> - Sähkösuunnittelija, EPC/urakoitsija tai datakeskusoperaattorin tekninen dokumentaatio; mittauksessa DCIM/BMS-toimittaja ja integraattori; energian todentamisessa sähköntoimittaja ja/tai operaattori. [6][7][9]
>
> **Minimissään**
> - Kokonaisenergia + IT-energia + UPS sisään/ulos siten, että häviöt ja energian kohdistus voidaan erottaa. [2]
>
> **Jos vaihe ohitetaan / tehdään puutteellisesti**
> - IT- ja infraenergia sekoittuvat, jolloin raportointi ja kohdistaminen perustuvat oletuksiin; häviöitä ei saada näkyviin mittauksen kautta. [2][7]

#### 5.1.2 Jäähdytys ja lämpötilanhallinta (sähkö → lämpö hallintaan)

IT-laitteiden käyttämä sähkö muuttuu käytännössä lämmöksi, joka poistetaan jäähdytysjärjestelmällä. Jäähdytysratkaisut (esim. ilma- ja vesipohjaiset järjestelmät, vapaajäähdytys, jäähdytyskoneet ja lämmönvaihtimet) sekä niiden kytkentä datakeskuksen kokonaisuuteen kuvataan suunnittelu- ja käsikirjalähteissä. [6][7]

Jäähdytyksen energiankulutus määräytyy ohjauksen ja osakuormakäyttäytymisen kautta (asetuspisteet, ilmavirrat/virtaamat, ohjauslogiikka). Operointivaiheen mittaus ja analyysi muodostavat perustan jäähdytyksen käytön säätämiselle ja vaikutusten todentamiselle. [4][7] Jäähdytyksen mittaus erotellaan omaksi kokonaisuudekseen, jotta sen osuus kokonaiskulutuksesta ja muutoksista voidaan tunnistaa. [2][4]

> **Tuotokset**
> - Jäähdytysjärjestelmän periaatekuvaus ja ohjausperiaatteet (asetuspisteet, osakuormakäyttäytyminen). [4][7]  
> - Mittauspisteet jäähdytykseen: sähkö (pumput, puhaltimet, chillerit/kuivajäähdyttimet), lämpötilat ja virtaamat/ilmavirrat (saatavuuden mukaan). [2][4][7]  
> - Käyttöönoton säätö- ja dokumentointiaineisto, jolla asetuspisteet ja ohjaus perustuvat mitattuun dataan. [4]
>
> **Mistä saat tämän?**
> - LVI/HVAC-suunnittelija ja automaatiointegraattori (BMS/DCIM), sekä commissioning-toimitus (järjestelmien toiminnan todennus). [4][7]
>
> **Minimissään**
> - Lämpötilamittaus ja jäähdytyksen sähkönkulutuksen seuranta sovitulla tarkkuudella, sekä mahdollisuus muuttaa asetuspisteitä ohjatusti. [2][4]
>
> **Jos vaihe ohitetaan / tehdään puutteellisesti**
> - Jäähdytys jää “muu kuorma” -luokkaan ilman erottelua; asetuspisteiden muutoksia ei voida kytkeä mitattuun vaikutukseen. [2][4]


### 5.2 Vaihe 2: Verkkopalvelupyynnöt internetistä palvelimille

#### 5.2.1 Verkko ja yhteydet (palvelu → liikenne → energiankulutus)

Käyttäjien palvelupyynnöt saapuvat datakeskukseen verkkoyhteyksien kautta ja ohjautuvat verkkolaitteiden kautta laskentaan. Verkon suunnittelussa tarkastellaan käytettävyyttä (reitit, operaattoriyhteydet, redundanssi) sekä energiankäyttöä (laitteiden kuormitus, energiatilat, linkkien ja kytkinten ohjaus kuorman mukaan). [1][8]

Verkon energiankäytön tarkastelu edellyttää liikenteen ja laitteiden kuormituksen mittaamista ja sen liittämistä kokonaisuuden seurantaan, jotta verkon osuus voidaan erottaa IT-energiassa ja muutokset tunnistaa. [1][8]

> **Tuotokset**
> - Verkon energiaprofiili: kulutus vs. liikenne sekä ohjausperiaatteet (energiamoodit, kapasiteetin käyttöpolitiikka). [8]  
> - Mittaus: liikenneprofiilit (esim. sisäinen/ulkoinen), laitetason tai verkon kokonaiskulutus sovitulla tasolla. [1][8]
>
> **Mistä saat tämän?**
> - Verkkosuunnittelija, operaattori ja/tai datakeskusoperaattorin dokumentaatio; mittaus integraation kautta DCIM/BMS-järjestelmiin. [8]
>
> **Minimissään**
> - Liikenneprofiilit ja verkon energiankulutuksen seuranta vähintään kokonaisuutena, jotta poikkeamat voidaan havaita. [8]
>
> **Jos vaihe ohitetaan / tehdään puutteellisesti**
> - Verkon energiankäyttö jää erottelematta, eikä sen vaikutusta kokonaiskulutukseen tai lämpökuormaan voida arvioida mittauksen kautta. [1][8]


### 5.3 Vaihe 3: Palvelinten toiminta ja lämmöntuotanto

#### 5.3.1 IT-palvelu: palvelimet, virtualisointi ja kuormanohjaus (sähkö → laskenta)

IT-energian muodostumiseen vaikuttavat palvelinten kuormitus, käyttöaste sekä se, miten työkuorma sijoitetaan (esim. virtualisointi, kontit, konsolidointi). Kuorman yhdistäminen ja dynaaminen sijoittelu ovat kirjallisuudessa esitettyjä keinoja vaikuttaa tyhjäkäyntiin ja energian käyttöön palvelutasojen rajoissa. [1][4]

Kuormanohjaus kytketään mittaukseen siten, että kuormamittarit (esim. käyttöasteet, resurssiprofiilit) ja energiadata voidaan tarkastella yhdessä. Tällä tuetaan kapasiteetin suunnittelua, poikkeamien tunnistamista ja vaikutusten todentamista. [1][4]

> **Tuotokset**
> - Kuormaprofiili ja kapasiteettisuunnitelma (palvelut, SLA/SLO, kasvu, huiput, varareservi-periaate). [1]  
> - Kuormanohjauksen periaatteet ja mittarointi (konsolidointi, mahdolliset tehorajat, automaation rajat). [1][4]  
> - Rajapinta mittaukseen: IT-energia ja kuormamittarit samaan seurantaan. [1]
>
> **Mistä saat tämän?**
> - Organisaation IT-arkkitehtuuri ja alusta-/pilvitiimi; tarvittaessa palveluntarjoaja (managed/colocation). [1]
>
> **Minimissään**
> - IT-energian ja käyttöasteiden seuranta sekä periaate, jolla pysyvää ylimitoitusta vältetään. [4]
>
> **Jos vaihe ohitetaan / tehdään puutteellisesti**
> - Tyhjäkäynti jää hallitsematta, ja energiankulutuksen muutos ei kytkeydy palvelutason mittareihin. [1][4]


### 5.4 Takaisin lämpönä: hukkalämmön talteenotto ja hyötykäyttö

#### 5.4.1 Hukkalämmön toimitusketju (lämpö → korvaava energia)

Datakeskuksen lämpö poistetaan jäähdytyksellä ja se voidaan johtaa ympäristöön tai siirtää hyötykäyttöön. Suomessa hukkalämmön hyötykäytön järjestäminen liittyy usein kaukolämpöön tai muuhun paikalliseen lämmönkäyttökohteeseen, sekä sopimuksiin ja mittaukseen, joilla toimitettu energia voidaan todentaa. [7][9]

Hukkalämmön hyödyntäminen kuvataan toimitusketjuna: (i) talteenoton tekninen ratkaisu ja rajapinta, (ii) vastaanottaja ja liityntä, (iii) sopimus ja vastuunjako, (iv) mittaus ja raportointi (toimitetut MWh). [9]

> **Tuotokset**
> - Talteenoton ja liitynnän tekninen ratkaisu (rajapinta, lämpötasot, tehot). [7]  
> - Sopimus- ja vastuunjakomalli (toimitusehdot, saatavuus, seisokit, hinnoittelu/maksumalli). [9]  
> - Mittaus ja raportointi: toimitettu lämpöenergia (MWh) ja siihen liittyvät mittauspisteet. [9]
>
> **Mistä saat tämän?**
> - LVI-suunnittelija (talteenotto ja rajapinta), lämpöyhtiö (liityntäehdot), integraattori (mittaus ja raportointi). [7][9]
>
> **Minimissään**
> - Suunnitelma ja mittausvalmius (tai LOI/sopimuspolku) hyötykäytön toteuttamiseksi vaiheittain. [9]
>
> **Jos vaihe ohitetaan / tehdään puutteellisesti**
> - Lämpö poistetaan ilman toimitetun energian todentamista; yhteys ilmastovaikutuksiin ja raportointiin jää puutteelliseksi. [9]


### 5.5 Mittaus, johtaminen ja jatkuva parantaminen

#### 5.5.1 Mittausketju ja toimintamalli (mittaa → analysoi → muutos → todenna)

Mittauksen tarkoitus on muodostaa ketju, jossa sähkönsyöttö, IT-kuorma, jäähdytys ja hukkalämpö voidaan erottaa, ja muutosten vaikutus voidaan todentaa. Mittaus ja mittareihin perustuva johtaminen esitetään kirjallisuudessa osana energiatehokkuuden ja vähähiilisyyden käytäntöjä. [2][4]

Mittausketju kuvataan kokonaisuutena (mittauspisteet → data → laskenta → raportointi → jäljitettävyys). Muutokset (esim. asetuspisteet, ohjauslogiikka, laitepäivitykset) liitetään hyväksyntään, jossa vaikutus tarkastetaan mittareista sovitulla jaksolla. [2][4]

> **Tuotokset**
> - Mittaus- ja raportointimalli: mittauspisteet → data → laskentasäännöt → näkymät/dashboards → audit trail. [2]  
> - Toimintamalli jatkuvaan parantamiseen: mittaa → analysoi → muutos → todenna → vakioi. [2]
>
> **Mistä saat tämän?**
> - DCIM/BMS-toimittaja ja integraattori (dataputki ja raportointi); operointimalli tilaajan omalta tiimiltä tai palveluntarjoajalta. [2]
>
> **Minimissään**
> - Kokonaisenergia ja IT-energia eroteltuna sekä jäähdytyksen energian seuranta; hukkalämmön MWh-mittaus, jos talteenotto on käytössä. [2]
>
> **Jos vaihe ohitetaan / tehdään puutteellisesti**
> - Vaikutuksia ei voida todentaa mittareista; päätöksenteko perustuu oletuksiin eikä raportointia voida jäljittää. [2]

#### 5.5.2 Ketjun yhteenveto

Datakeskuksen toiminta muodostuu kokonaisuudesta, jossa sähkö, IT, verkko, jäähdytys ja lämpö ovat kytkeytyneitä. Suomessa vihreän datakeskuksen toteutus kytkeytyy tyypillisesti (i) uusiutuvan sähkön todentamiseen ja raportointiin, (ii) IT-kuorman ohjaukseen, (iii) verkon mittaukseen ja ohjaukseen, (iv) jäähdytyksen mittaukseen ja osakuormakäyttäytymiseen, (v) hukkalämmön toimitusketjuun sekä (vi) mittaus- ja johtamismalliin, joka tuottaa seurannan ja todennuksen. [1–4][6–9]

> **Koontituotos**
> - Raportoitava toimintamalli: energiamittaus (kokonais/IT/jäähdytys) + uusiutuvan ja päästöjen todentaminen + hukkalämmön MWh-mittaus, jos hyötykäyttö on toteutettu. [2][9]
>
> **Jos ketju jää osa-alueiksi**
> - Kokonaisvaikutusta ei saada näkyviin mittauksessa ja raportoinnissa, ja toimenpiteiden kohdistaminen jää epäselväksi. [2]


## Lähteet

[1] Jin, X., Zhang, Y., Vasilakos, A. V., & Liu, Z. (2016). *Green data centers: A survey, perspectives, and future directions* (arXiv:1608.00687).

[2] Uddin, M., & Rahman, A. A. (2012). Energy efficiency and low carbon enabler green IT framework for data centers considering green metrics. *Renewable and Sustainable Energy Reviews, 16*(6), 4078–4094.

[3] Pierson, J.-M., Baudic, G., Caux, S., Celik, B., Costa, G., Grange, L., … Varnier, C. (2019). DATAZERO: Datacenter with zero emission and robust management using renewable energy. *IEEE Access*.

[4] Sharma, P., Pegus II, P., Irwin, D. E., Shenoy, P., Goodhue, J., & Culbert, J. (2017). Design and operational analysis of a green data center. *IEEE Internet Computing, 21*(4), 16–24.

[5] *Energy storage techniques, applications, and recent trends – A sustainable solution for power storage*. (n.d.). Tekijä- ja julkaisudata täsmennettävä ennen julkaisemista.

[6] Barroso, L. A., Clidaras, J., & Hölzle, U. (2013). *The datacenter as a computer: An introduction to the design of warehouse-scale machines* (2nd ed.). Morgan & Claypool.

[7] Geng, H. (Ed.). (2014). *Data center handbook*. John Wiley & Sons.

[8] Bilal, K., Malik, S. U. R., Khalid, O., Hameed, A., Alvarez, E., Wijaysekara, V., … Khan, S. U. (2014). A taxonomy and survey on green data center networks. *Future Generation Computer Systems, 36*, 189–208.

[9] Liikenne- ja viestintäministeriö. (2020). *The ICT sector, climate and the environment – Interim report* (Publications of the Ministry of Transport and Communications 2020:14).



## 6. Energian kulutus ja uudelleenkäyttö


Tässä kappaleessa käsitellään, mistä datakeskuksen kWh-lukemat muodostuvat, miten työkuorma ja tietoliikenne näkyvät kulutuksessa, miten kulutus vaihtelee ajassa, mikä on jäähdytyksen rooli sekä mitä hukkalämpö tarkoittaa ja miten sitä voidaan hyödyntää. Lisäksi kuvataan, miten energiankäyttö sidotaan päästöihin ja miten luvut viedään raportointiin ja indikaattoreihin standardoidulla tavalla. Energiadata ja sen rakenteet ovat pohja myöhemmälle, analytiikkaan perustuvalle optimoinnille (menetelmäopas jatkaa tästä).


### 6.1 Peruskuva: mistä kWh:t syntyvät

### Miksi?

* kWh on laskutuksen ja energiaraportoinnin perusyksikkö: se kuvaa kulutettua energiaa ajan yli (teho kW integroituna ajassa). Ilman yhteistä määrittelyä siitä, mitä mitataan ja mistä mittausrajasta, eri kohteiden ja eri kuukausien luvut eivät ole vertailukelpoisia.
* Datakeskuksessa “kokonaisenergia” sisältää IT-laitteiden energian (palvelimet, tallennus, verkko) ja tukijärjestelmien energian (jäähdytys, sähkönjakelu/UPS-häviöt, valaistus ja muu infrastruktuuri). PUE-metriikka on standardoitu tapa kuvata tätä suhdetta. [1]

### Mitä tehdään?

* Määritetään mittausrajat (control volume) ja energian virrat:

  * sisään: verkkosähkö ja mahdollinen oma tuotanto
  * sisäinen käyttö: IT-laitteet + tukikuormat
  * ulos: lämpö (käytännössä lähes kaikki sähkö muuttuu lämmöksi tilassa), mahdollinen uudelleenkäyttö (hukkalämpö) ja häviöt.
* Sovitaan mittaus- ja raportointitapa PUE:lle (mittauspisteet, ajallinen resoluutio, raportointijakso). Standardi määrittää PUE:n laskennan ja raportoinnin periaatteet sekä mittauskategorioita. [1]
* Rakennetaan perusenergiatase: “laitosenergia” vs. “IT-energia” sekä karkea alajakautuma (jäähdytys / sähköketju / muu). Tukena voidaan käyttää laiteluokkajakoa (servers, storage, network, cooling, other) yleisellä tasolla. [2]

### Tuotokset

* Energian mittausrajakuvaukset (yksinkertainen kaavio ja sanallinen määrittely).
* Mittauspiste- ja mittarilista (pääkeskus/utility, UPS-lähdöt, jäähdytyksen syötöt, mahdollinen rack-/PDU-mittaus).
* Ensimmäinen PUE-laskenta ja raportointisääntö (mitä raportoidaan, millä jaksolla). [1]

### Jos vaihe tehdään huonosti / ohitetaan

* Kokonaiskulutus ja IT-kulutus sekoittuvat (PUE vääristyy) ja toimenpiteiden vaikutus jää epäselväksi.
* Mittaus ei kata kriittisiä kuormia (esim. jäähdytyksen osia tai UPS-häviöitä), jolloin optimointi kohdistuu virheelliseen “suurimpaan” kuluerään.
* Myöhemmän analytiikan lähtötaso puuttuu: poikkeamia ei tunnisteta eikä ennusteita voi sitoa todellisiin mittauksiin.

### 6.2 Miten tietoliikenne ja työkuorma näkyvät kWh-luvuissa

### Miksi?

* IT-energian sisällä kulutus jakautuu palvelimiin, tallennukseen ja verkkolaitteisiin. Näillä on eri kuormitusprofiilit: osa kulutuksesta on kuormaan sidottua, osa perustasoa (idle). [2]
* Palvelinlaitteiden energiankäyttö ei historiallisesti ole ollut täysin “energiaproportionaalista” (kulutus ei laske lineaarisesti kuorman mukana), mikä tekee kuormanohjauksesta ja konsolidoinnista keskeisen energiamuuttujan. [4]
* Datakeskusten lisäksi myös datansiirtoverkot kuluttavat sähköä merkittävässä mittakaavassa, ja palvelun kokonaisvaikutus voi ulottua datakeskuksen rajojen ulkopuolelle (erityisesti, jos palvelutasolla raportoidaan laajemmin ICT-palvelun energiankäyttöä). [3]

### Mitä tehdään?

* Liitetään energiamittaus työkuorma- ja verkkomittareihin:

  * työkuorma: CPU/GPU-utilisaatio, muistikuorma, I/O, jobit/tapahtumat, virtuaalikoneiden/containerien määrä
  * tietoliikenne: sisäinen läpivienti (east-west), ulkoinen liikenne (north-south), porttien käyttöaste, reitittimien/kytkinten kuorma.
* Rakennetaan perusmalli “energia per tuotettu palvelu” -ajatteluun:

  * kWh per transaktio / kWh per jobi / kWh per GB siirrettyä dataa (valitaan palvelukohtaisesti).
* Varmistetaan, että IT-energian määrittelyyn sisältyvät myös verkkolaitteet, jos niitä käytetään PUE/IT-energia -jaottelussa. [1]

### Tuotokset

* Mittauskartta: mitkä kuormitus- ja verkkometriikat kerätään ja mihin energiamittauksiin ne yhdistetään.
* Perusraportti: “IT-energia jaettu palvelimet/tallennus/verkko” sekä vastaavat kuormamittarit samalla aikajanalla. [2]
* Yksi tai useampi palvelukohtainen intensiteetti-indikaattori (esim. kWh/jobi tai kWh/GB), jota voidaan käyttää kapasiteetti- ja optimointikeskusteluissa. [4]

### Jos vaihe tehdään huonosti / ohitetaan

* Energiankulutus nähdään vain kuukausisummaa kohti, eikä erotu, johtuuko muutos työkuormasta, verkosta, jäähdytyksestä vai häviöistä.
* Kapasiteettisuunnittelu perustuu huipputehon oletuksiin ilman palvelutasomittareita, mikä kasvattaa ylimitoituksen riskiä.
* Monitoimijaympäristössä (colocation) kulutusta ei pystytä kohdistamaan asiakkaalle/kuormalle, mikä vaikeuttaa kustannus- ja päästöallokointia.


### 6.3 Kulutusprofiilit ja kuormituksen vaihtelu

### Miksi?

* Datakeskuksen energiankäyttö muodostuu samanaikaisesti:

  * kuormaan sidotusta osasta (IT ja osa jäähdytyksestä)
  * perustasosta (jatkuva infrastruktuurikuorma, osa IT-laitteiden idle-tehosta). [4]
* Ajallinen vaihtelu (päivä/viikko/vuosi) vaikuttaa sekä energiakustannuksiin (tehomaksut, tariffit) että jäähdytyksen tarpeeseen (ulkoilma ja vuodenaika).
* EU:n energiatehokkuusdirektiivin raportointikehikko edellyttää vuosittaista seurantaa ja julkistamista tietyille kynnyskokoa suuremmille datakeskuksille, mikä tekee profiilien muodostamisesta käytännön vaatimuksen monissa ympäristöissä. [12]

### Mitä tehdään?

* Rakennetaan kuormitus- ja kulutusprofiilit vähintään kolmella aikajaksolla:

  * vuorokausi: huiput, yökuorma, ajoitetut batchit
  * viikko: arki vs. viikonloppu
  * vuosi: kesä/talvi, lämpötila- ja jäähdytysvaikutus.
* Erotellaan kokonaiskulutus vähintään kahteen pääkomponenttiin:

  * IT-energia
  * ei-IT-energia (jäähdytys + sähköketju + muu).
* Tunnistetaan “minimikuorma” (baseload) ja “huippukuorma” (peak), ja kirjataan mitkä järjestelmät määrittävät huipun.

### Tuotokset

* Aikasarja- ja profiilikuvaus: kW ja kWh (kokonaisuus, IT, jäähdytys) sovitulla resoluutiolla (esim. 15 min tai 1 h).
* Kuormituskalenteri: tunnetut työkuormapiikit ja ajoitetut ajot (ylläpito, varmistukset, malliajojen ikkunat).
* Lista toimenpidekohteista, jotka vaikuttavat joko baseloadiin tai huippuun (erotellaan tarkoituksella).

### Jos vaihe tehdään huonosti / ohitetaan

* Optimointi kohdistuu kuukausisummaa pienentäviin keinoihin, vaikka kustannus muodostuu tehohuipuista tai jäähdytyksen kausivaihtelusta.
* Raportoinnissa näkyy ristiriitoja (esim. PUE “paranee” vain siksi, että IT-kuorma nousi, vaikka jäähdytyksen ohjaus ei muuttunut). [1]
* Hukkalämmön hyödyntämisen mitoitus tehdään keskiarvoilla, jolloin lämpöteho tai lämpötilataso ei riitä lämmityskauden huippuun.


##¤ 6.4 Jäähdytyksen osuus energiankulutuksesta

### Miksi?

* Jäähdytys ja muu infrastruktuuri muodostavat mitattavan osan datakeskuksen sähköstä. IEA:n laiteluokkajaottelussa “cooling” on oma pääluokkansa kokonaiskulutuksessa. [2]
* Jäähdytyksen energiankäyttö riippuu IT-kuormasta, lämmönsiirtoratkaisusta (ilma/neste), tavoitelämpötiloista sekä ulko-olosuhteista.
* Jäähdytyksen tehokkuutta voidaan mitata standardoidulla KPI:llä (Cooling Efficiency Ratio, CER). [5]
* Lämpötila- ja ympäristörajat määräytyvät IT-laitteiden käyttöympäristön mukaan; ASHRAE:n ohjeistus kuvaa datakeskusten lämpötilakäytäntöjen kehitystä ja käyttöympäristöluokkia (ml. nestekierto). [6]

### Mitä tehdään?

* Erotellaan jäähdytyksen sähkö kulutusmittauksilla omaksi lohkokseen (chillerit, pumput, puhaltimet, CRAH/CRAC, kuivajäähdyttimet, mahdolliset jäähdytystornit).
* Kirjataan ohjausmuuttujat ja niiden mittaus:

  * lämpötilan asetusarvot (supply/return)
  * ilman/nesteen virtaamat ja lämpötilat (jos saatavilla)
  * ulkolämpötila ja mahdollinen vapaajäähdytyksen käyttö.
* Lasketaan ja raportoidaan CER, tai vähintään jäähdytyksen kWh ja sen osuus kokonaiskWh:sta sovitulla jaksolla. [5]

### Tuotokset

* Jäähdytyksen sähkönkulutuksen aikasarja ja osuus kokonaiskulutuksesta. [2]
* Jäähdytyksen KPI (CER) tai vastaava sisäinen mittari, joka perustuu standardin mukaiseen määrittelyyn. [5]
* Asetusarvopolitiikka: mitkä lämpötila-alueet ovat käytössä ja millä perusteella (sidotaan IT-laitteiden ympäristövaatimuksiin). [6]

### Jos vaihe tehdään huonosti / ohitetaan

* Jäähdytyksen kulutus jää “muu kuorma” -luokkaan, jolloin muutokset näkyvät vain PUE:ssa ilman selitystä. [1]
* Asetusarvoja muutetaan ilman mittausta, mikä voi siirtää ongelman ilmavirroista paikallisiin hotspotteihin.
* Hukkalämmön hyödyntämisen mahdollisuus jää arvioimatta, koska lämpötilataso ja lämpöteho eivät ole mitattuna.

### 6.5 Mitä hukkalämmöllä tarkoitetaan

### Miksi?

* Datakeskus muuntaa sähkön lämmöksi IT-laitteissa ja tukijärjestelmissä; tämä lämpö poistetaan jäähdytyksellä ja päätyy tyypillisesti ulkoilmaan tai vesipiiriin.
* Hukkalämmöllä tarkoitetaan lämpöenergiaa, joka syntyy prosessin sivutuotteena ja jota ei käytetä kohteessa hyödyksi. Datakeskuksissa lämpö on usein “matalalämpöistä”; IRENA kuvaa tyypillisiä lämpötilatasoja noin 25–40 °C esimerkkinä datakeskushukkalämmöstä. [9]
* Uudelleenkäyttöä voidaan kuvata standardoidulla mittarilla Energy Reuse Factor (ERF), joka mittaa datakeskuksesta uudelleenkäytettävän energian suhdetta kokonaiskulutettuun energiaan. [7]
* Lisäksi on käytössä mittarikehikkoja, jotka on rakennettu tekemään uudelleenkäyttö näkyväksi datakeskusmittareissa (esim. The Green Gridin ERE-lähestymistapa). [8]

### Mitä tehdään?

* Määritetään hukkalämmön syntypiste ja keräystapa:

  * ilmajäähdytys: poistoilman lämpö ja ilmamäärä
  * nestekierto: paluu-/menolämpötilat ja virtaama
  * lauhdutinpuoli (jäähdytyskoneet): missä lämpö vapautuu ympäristöön.
* Arvioidaan “hyödynnettävä lämpö” kolmella peruskysymyksellä:

  1. paljonko lämpötehoa on saatavilla (kWth) eri kuormilla
  2. mikä on lämpötilataso (°C)
  3. missä ajassa ja millä vaihtelulla lämpö on saatavilla (profiilit).
* Valitaan mittari, jolla uudelleenkäyttö raportoidaan (ERF, ja tarvittaessa ERE). [7] [8]

### Tuotokset

* Hukkalämmön inventaario: lämpöteho, lämpötilataso, saatavuusprofiili (päivä/viikko/vuosi).
* Rajapintakuvaus: mitä luovutetaan (vesi/ilma), mitkä lämpötilat ja virtaamat, mihin mittaus perustuu.
* ERF-laskennan edellyttämä mittausmäärittely ja mittauspisteet. [7]

### Jos vaihe tehdään huonosti / ohitetaan

* Hukkalämmön lämpötilataso oletetaan vääräksi (esim. ilman lämpöpumppua luvataan lämpöä lämpöverkkoon), jolloin integraatio ei täytä vastaanottajan vaatimuksia.
* Lämpömäärä arvioidaan nimellistehosta, vaikka käytännön kuormitus ei yllä mitoitushetken oletuksiin.
* Uudelleenkäyttö jää raportoimatta, jolloin vaikutus ei näy energiadataan eikä sidosryhmäraportointiin. [7]


### 6.6 Konkreettiset esimerkit hukkalämmön hyödyntämisestä

### Miksi?

* Esimerkit konkretisoivat kaksi asiaa: (1) mihin lämpö voidaan ohjata ja (2) millaisia toimijoita ja sopimusmalleja ketju vaatii (datakeskus–operaattori–lämpöyhtiö–loppukäyttäjä).
* Useissa toteutuksissa keskeinen mahdollistaja on olemassa oleva kaukolämpöverkko ja liittymämalli ylimääräisen lämmön syöttämiseksi verkkoon. [10] [11]

### Mitä tehdään?

* Tyypillisiä toteutuspolkuja:

  1. **Syöttö kaukolämpöön**: datakeskuksen lämpö kerätään (usein lämpöpumpulla lämpötilaa nostamalla) ja siirretään lämpöyhtiön verkkoon.

     * Esimerkkejä: Microsoft–Fortum -kokonaisuuden tavoite hyödyntää datakeskusten lämpöä rakennusten lämmityksessä pääkaupunkiseudulla. [13] [14]
     * Esimerkkejä: Googlen Hamina-projekti, jossa datakeskuksen lämpö ohjataan paikalliseen kaukolämpöön yhteistyössä energiayhtiön kanssa. [15] [16]
  2. **Kaupunkitason “open district heating” -malli**: verkko-operaattori tarjoaa menettelyn, jossa ulkopuolinen toimija voi myydä tai luovuttaa ylijäämälämpöä verkkoon.

     * Esimerkki: Stockholm Exergin “Open District Heating” -konsepti ja lämmön talteenotto datakeskus- ja teollisuuskohteista. [11]
  3. **Lämmön käyttö jäähdytyksen tuottamiseen**: hukkalämpöä käytetään esimerkiksi absorptiojäähdytyksen ajamiseen tai muuhun on-site -ratkaisuun (toteutus riippuu lämpötilatasosta ja järjestelmästä).

     * Esimerkkityyppinä kuvattu ERE-mittariston yhteydessä: lämmön käyttö absorptiojäähdyttimen ajamiseen ja hyötykäyttö muualla kampuksella. [8]

### Tuotokset

* Valittu toteutusarkkitehtuuri (kaukolämpö / open DH / on-site -käyttö).
* Vastuunjako ja mittaus: mitä mitataan datakeskuksessa ja mitä verkossa (lämpömäärämittaus, lämpötilat, toimitettu energia).
* Sopimusrunko (toimitusehdot, lämpötehon saatavuus, hinnoittelu/maksumalli, seisokkien käsittely).

### Jos vaihe tehdään huonosti / ohitetaan

* Lämpö toimitetaan ilman yhteistä mittaus- ja vastuunjakomallia, jolloin toimitettu energiamäärä ja hyvitys jää epäselväksi.
* Lämmön saatavuus ei vastaa lämpöverkon tarvetta (kausivaihtelu) ja projekti jää “teknisesti toimivaksi mutta käytännössä vajaakäyttöiseksi”.
* Ratkaisu lukitaan yhteen käyttötapaan ilman vaihtoehtoista lämpönielua (esim. vain kaukolämpö ilman varapolkua), jolloin käyttökatkot kasvavat.


### 6.7 Milloin hukkalämmön hyödyntäminen on taloudellisesti optimaalisinta

### Miksi?

* Kannattavuus muodostuu yleensä kolmesta tekijästä:

  1. **liitynnän ja siirron kustannus** (putkivedot, lämmönsiirrin, lämpöpumppu, sähköliittymä)
  2. **hyödynnetyn lämmön määrä ja lämpötilataso**
  3. **korvattavan lämmön tuotantotapa ja hinta** (esim. polttoaineet, sähkölämpö, lämpöpumput).
* IRENA nostaa esiin, että datakeskusten hukkalämmön talteenotto kytkeytyy erityisesti kaukolämpö- ja -jäähdytysverkkoihin sekä mahdollisuuteen varastoida kesän lämpöä talven tarpeisiin. [9]

### Mitä tehdään?

* Tehdään esiselvitys, jossa lasketaan:

  * toimitettava lämpöenergia (MWh/a) kuormitusprofiilin perusteella
  * tarvittava lämpötilan nosto ja lämpöpumpun sähkö (jos käytetään lämpöpumppua)
  * investoinnit ja ylläpito (CAPEX/OPEX)
  * tulot/hyödyt (lämmön myynti, korvattu lämmöntuotanto, mahdolliset sopimuskorvaukset).
* Valitaan mittari ja raportointitapa, jolla hyödyntäminen todennetaan (ERF ja/tai muu lämpöenergian todennus). [7]
* Huomioidaan sääntely- ja raportointirajat: EU:n energiatehokkuusdirektiivissä on kytkentöjä hukkalämmön hyödyntämisen tarkasteluun ja kustannus–hyötyarviointeihin (erityisesti suuremmissa kohteissa). [12]

### Tuotokset

* Kannattavuuslaskelma ja herkkyysanalyysi (lämmön hinta, sähkön hinta, kuorman vaihtelu, lämpöpumpun käyttö).
* Mitoitus (kWth, virtaamat, lämpötilat) ja liityntäsuunnitelma.
* Mittaus- ja todennusmalli (lämpömäärämittaus + ERF-laskennan perusta). [7]

### Jos vaihe tehdään huonosti / ohitetaan

* Lämmönluovutus mitoitetaan nimelliskuormalle ilman kuormaprofiilia, jolloin toteutunut vuosihyöty jää suunniteltua pienemmäksi.
* Lämpöpumpun sähkönkulutus tai tehomaksut jäävät huomioimatta, jolloin nettosäästö ei vastaa laskelmaa.
* Sopimus (toimitusvelvoite vs. saatavuus) jää epäselväksi ja riskit realisoituvat seisokeissa.


### 6.8 Milloin hukkalämmön hyödyntäminen on ekologisesti optimaalisinta

### Miksi?

* Ekologinen hyöty syntyy, jos hukkalämmöllä korvataan lämmöntuotantoa, jonka päästöintensiteetti on korkeampi kuin talteenoton ja siirron aiheuttamat päästöt (esim. lämpöpumpun käyttämä sähkö). Tämä edellyttää eksplisiittistä päästölaskentaa.
* IRENA kuvaa hukkalämmön talteenoton tuovan ympäristöhyötyjä, kun muuten hukkaan menevä lämpö käytetään lämmitykseen ja datakeskuksen energia voidaan kytkeä järjestelmätasolla tarkoituksenmukaisiin ratkaisuihin (esim. DHC-verkot ja varastointi). [9]

### Mitä tehdään?

* Lasketaan “nettopäästövaikutus” per toimitettu lämpöyksikkö:

  * päästöt, jotka syntyvät talteenoton ja lämpötilan noston sähköstä (jos käytössä)
  * miinus päästöt, jotka vältetään korvaamalla toista lämmöntuotantoa.
* Sidotaan laskenta organisaation GHG-raportointiin (Scope 2 sähkö, ja tarvittaessa erikseen vaikutus korvattuun lämpöön).
* Raportoidaan datakeskuksen hiili-intensiteetti standardoidulla KPI:llä (CUE) ja erotetaan energiamittarit (PUE/REF/ERF) päästömittareista. [17] [1] [2]

### Tuotokset

* Päästölaskennan periaatteet ja käytetyt päästökertoimet (dokumentointi).
* Yksi päätösindikaattori: esim. “tCO₂e vältetty / MWh toimitettu lämpö” + epävarmuusraja.
* CUE-raportti datakeskuksen käyttöaikaisista CO₂-päästöistä ja sen taustadatat (energia, energialähde). [17]

### Jos vaihe tehdään huonosti / ohitetaan

* Hukkalämmön “hyöty” raportoidaan vain toimitettuna lämpönä, vaikka nettovaikutus riippuu sähköstä ja korvatusta lämmöstä.
* Päästölukuja ei voi auditoida (puuttuvat kertoimet, rajaukset ja laskentasäännöt).
* Päätöksenteko ohjautuu pelkkään energiamäärään (MWh) ilman hiili-intensiteettiä.


### 6.9 Energian käytön ja päästöjen yhteys

### Miksi?

* Energian määrä (kWh) ja päästöt (tCO₂e) liittyvät toisiinsa päästökertoimien kautta, mutta yhteys ei ole vakio: sama kWh voi tuottaa eri määrän päästöjä riippuen sähkön tuotantorakenteesta ja hankintamallista.
* GHG Protocolin Scope 2 -ohjeistus on keskeinen viitekehys ostosähkön epäsuorien päästöjen raportointiin (menetelmät ja läpinäkyvyysvaatimukset). [18]
* Datakeskuksille on olemassa standardoituja KPI-mittareita, jotka tukevat vertailua ja raportointia:

  * PUE (kokonaisenergia / IT-energia) [1]
  * REF (uusiutuvan sähkön osuutta kuvaava tekijä) [19]
  * ERF (uudelleenkäytetyn energian osuus) [7]
  * CER (jäähdytyksen tehokkuusmittari) [5]
  * CUE (CO₂-intensiteetti käyttöaikana) [17]
* EU:n energiatehokkuusdirektiivi velvoittaa jäsenmaita edellyttämään tietyn kokoluokan datakeskuksilta vuosittaista energiasuorituskykytiedon seurantaa ja julkistamista (kynnys: asennettu IT-tehontarve vähintään 500 kW; aikataulut ja liitteet määrittävät sisältöä). [12]

### Mitä tehdään?

* Tehdään näkyväksi kolme tasoa:

  1. **Energia**: kokonaiskWh, IT-kWh, jäähdytys-kWh, uusiutuva kWh (sovittu rajaus).
  2. **Päästöt**: tCO₂e (Scope 2) ja tarvittaessa täydentävät kategoriat (esim. polttoaineet).
  3. **Indikaattorit**: PUE, REF, ERF, CER, CUE sekä valitut palvelukohtaiset intensiteetit (kWh/jobi).
* Rakennetaan raportointiputki:

  * mittausdata → laadunvarmistus (puuttuvat arvot, kalibrointi) → KPI-laskenta → julkaisu/raportti → audit trail.
* Dokumentoidaan rajaukset (mitä sisältyy datakeskukseen; mitä ei), koska se vaikuttaa sekä KPI-lukuihin että sääntelyraportointiin. [12] [1]

### Tuotokset

* Vuosikello: mitä raportoidaan kuukausittain ja vuosittain (energia, KPI:t, päästöt).
* KPI-määrittelydokumentti (PUE/REF/ERF/CER/CUE) ja laskentasäännöt organisaation sisällä. [1] [19] [7] [5] [17]
* Julkaisukelpoinen raportti tai dashboard, jossa näkyy:

  * kulutus (kWh), teho (kW), profiilit
  * uusiutuvan sähkön osuus
  * hukkalämmön toimitus ja ERF
  * päästöt ja CUE. [12]

### Jos vaihe tehdään huonosti / ohitetaan

* Energia ja päästöt raportoidaan irrallaan ilman yhteistä data- ja laskentaketjua; muutosten syy ei löydy.
* KPI:t muuttuvat raportista toiseen, koska mittausrajat tai laskentasäännöt eivät ole dokumentoituja.
* Sääntelyraportoinnissa syntyy aukkoja (puuttuva data tai puutteelliset määrittelyt), ja sisäinen optimointi perustuu epätasalaatuiseen mittaukseen. [12]


## Lähteet

1. ISO: *ISO/IEC 30134-2:2016 – Power usage effectiveness (PUE): määrittely, mittaus, laskenta ja raportointi.* ([ISO][1])
2. International Energy Agency (IEA): *Share of electricity consumption by data centre and equipment type, 2024 (servers, storage, network, cooling, other infrastructure).* ([IEA][2])
3. IEA: *Data centres and data transmission networks – kumpikin noin 1–1,5 % globaalista sähkönkulutuksesta; taustoitus digitalisaation energiankäytöstä.* ([IEA][3])
4. Barroso & Hölzle (2007): *The Case for Energy-Proportional Computing – energiaproportionaalisuuden tausta ja palvelinten kuormariippuvuus.* ([barroso.org][4])
5. ISO: *ISO/IEC 30134-7:2023 – Cooling efficiency ratio (CER) jäähdytyksen KPI:nä.* ([ISO][5])
6. ASHRAE: *Data center thermal guidelines -materiaali (ilma- ja nestekiertoympäristöt, käyttöalueiden kehitys).* ([ASHRAE Dallas Chapter][6])
7. ISO: *ISO/IEC 30134-6:2021 – Energy Reuse Factor (ERF): uudelleenkäytetyn energian osuus.* ([ISO][7])
8. The Green Grid / LBNL: *ERE: A metric for measuring the benefit of reuse energy from a data center (ERE/ERF- jaottelun tausta ja esimerkkikäyttö).* ([Data Center Efficiency Center][8])
9. IRENA: *Waste heat recovery from data centres – lämpötilatasot, DHC-kytkennät ja järjestelmätason tarkastelu.* ([IRENA][9])
10. EU Covenant of Mayors: *Stockholm: Heat recovery from data centres – kaukolämpöinfrastruktuurin rooli ja konseptit.* ([eu-mayors.ec.europa.eu][10])
11. Stockholm Exergi: *Heat recovery / Open District Heating – ylijäämälämmön syöttö verkkoon.* ([stockholmexergi.se][11])
12. EU: *Directive (EU) 2023/1791 (Energy Efficiency Directive), Article 12 ja Annex VII – datakeskusten seuranta- ja julkaisukynnykset (mm. 500 kW) ja raportoitavat tiedot.* ([EUR-Lex][12])
13. Fortum: *Datacentres Helsinki region – Fortum & Microsoft -hankkeen kuvaus hukkalämmön hyödyntämisestä.* ([Fortum][13])
14. AFRY: *Capturing data centre waste heat for Fortum’s district heating in Finland – hankekuvaus ja roolit.* ([Afry][14])
15. Google: *Our first offsite heat recovery project lands in Finland – Hamina, kaukolämpö ja aikataulutus.* ([blog.google][15])
16. Data Center Dynamics: *Google launches heat recovery project at data center in Hamina, Finland – toteutus ja kumppanit.* ([Data Center Dynamics][16])
17. ISO: *ISO/IEC 30134-8:2022 – Carbon Usage Effectiveness (CUE): käyttöaikaisen CO₂-intensiteetin KPI.* ([ISO][17])
18. GHG Protocol: *Scope 2 Guidance – ostosähkön päästöjen raportoinnin periaatteet ja läpinäkyvyys.* ([ghgprotocol.org][18])
19. ISO: *ISO/IEC 30134-3:2016 – Renewable Energy Factor (REF): uusiutuvan sähkön käytön kvantitatiivinen mittari.* ([ISO][19])

[1]: https://www.iso.org/standard/63451.html?utm_source=chatgpt.com "ISO/IEC 30134-2:2016 - Information technology — Data centres — Key ..."
[2]: https://www.iea.org/data-and-statistics/charts/share-of-electricity-consumption-by-data-centre-and-equipment-type-2024?utm_source=chatgpt.com "Share of electricity consumption by data centre and equipment type, 2024"
[3]: https://www.iea.org/energy-system/buildings/data-centres-and-data-transmission-networks?utm_source=chatgpt.com "Data centres & networks - IEA - International Energy Agency"
[4]: https://www.barroso.org/publications/ieee_computer07.pdf?utm_source=chatgpt.com "Case for Energy-Proportional Computing - Barroso"
[5]: https://www.iso.org/standard/80493.html?utm_source=chatgpt.com "ISO/IEC 30134-7:2023 - Information technology — Data centres key ..."
[6]: https://dallas-ashrae.org/images/meeting/041625/the_ashrae_thermal_guidelines_for_data_centers_____past__present_and_future.pdf?utm_source=chatgpt.com "The ASHRAE Thermal Guidelines for Data Centers Past, Present, and Future"
[7]: https://www.iso.org/standard/71717.html?utm_source=chatgpt.com "ISO/IEC 30134-6:2021 - Information technology — Data centres key ..."
[8]: https://datacenters.lbl.gov/sites/default/files/EREmetric_GreenGrid.pdf?utm_source=chatgpt.com "ERE: A METRIC FOR MEASURING THE BENEFIT OF REUSE ENERGY FROM A DATA CENTER"
[9]: https://www.irena.org/Innovation-landscape-for-smart-electrification/Power-to-heat-and-cooling/31-Waste-heat-recovery-from-data-centres "31 Waste heat recovery from data centres"
[10]: https://eu-mayors.ec.europa.eu/en/news/stockholm-sweden-heat-recovery-data-centres?utm_source=chatgpt.com "Stockholm, Sweden : Heat recovery from data centres"
[11]: https://www.stockholmexergi.se/en/heat-recovery/?utm_source=chatgpt.com "Heat recovery - Stockholm Exergi"
[12]: https://eur-lex.europa.eu/eli/dir/2023/1791/oj/eng "Directive - 2023/1791 - EN - EUR-Lex"
[13]: https://www.fortum.com/data-centres-helsinki-region?utm_source=chatgpt.com "Fortum and Microsoft's datacentre project spearheads energy efficiency"
[14]: https://afry.com/en/project/capturing-data-center-waste-heat-fortums-district-heating-in-finland?utm_source=chatgpt.com "Capturing data centre waste heat for Fortum’s district heating in ..."
[15]: https://blog.google/around-the-globe/google-europe/our-first-offsite-heat-recovery-project-lands-in-finland/?utm_source=chatgpt.com "Our first offsite heat recovery project lands in Finland"
[16]: https://www.datacenterdynamics.com/en/news/google-launches-heat-recovery-project-at-data-center-in-hamina-finland/?utm_source=chatgpt.com "Google launches heat recovery project at data center in Hamina, Finland ..."
[17]: https://www.iso.org/standard/77691.html?utm_source=chatgpt.com "ISO/IEC 30134-8:2022 - Information technology — Data centres key ..."
[18]: https://ghgprotocol.org/scope-2-guidance?utm_source=chatgpt.com "Scope 2 Guidance - GHG Protocol"
[19]: https://www.iso.org/standard/66127.html?utm_source=chatgpt.com "ISO/IEC 30134-3:2016 - Information technology — Data centres — Key ..."


## 7. Datakeskuksen energiatehokkuuden mittaaminen
- Mittaristo: PUE, DCiE, CUE, WUE ja muut tunnusluvut  
- Mittauspisteiden suunnittelu: pääsyöttö, UPS, PDU, jäähdytys, IT  
- Benchmarkkaus ja raportointi: energiaprofiilien keruu, vuorokausi- ja kuukausitrendit  
- Yhtenäiset kansalliset raportointivaatimukset: Blue Angel, ICT-sektorin indikaattorityö

Mittarit (todistettavuus ja jatkuva parantaminen)
Tavoite: vihreys = mitattu ja johdettu, ei väitetty.
Sisällytä:
Mitä mitataan: IT-kuorma, kokonaissähkö, jäähdytys, lämpö talteen, vesi (jos relevantti).
Ydinmittarit: esim. PUE + hukkalämmön hyödyntämisen mittari + uusiutuvan sähkön osuus (pidä mittaristo pienenä).
Mittaripistekartta: missä anturit/mittarit ovat ja mitä niistä raportoidaan.
Raportointirytmi ja “toimenpideraja-arvot” (milloin reagoidaan).


Yhteenveto + tarkistuslistat


# Sanasto

## Sanasto (Termi – Selitys)

| Termi | Selitys |
|---|---|
| Datakeskus | Fyysinen ympäristö, jossa tuotetaan laskenta-, tallennus- ja verkkopalveluja (IT-laitteet + sähkö, jäähdytys, valvonta). |
| Vihreä datakeskus | Datakeskus, jonka suunnittelu ja operointi on optimoitu energiatehokkuuden ja ympäristövaikutusten (mm. CO₂) minimointiin mitattavasti. |
| IT-kuorma (IT load) | Palvelimien, verkon ja tallennuksen käyttämä sähköteho/energia; PUE-laskennan nimittäjä. |
| Facility load | Koko laitoksen sähkökuorma (IT + jäähdytys + sähköketjun häviöt + muut tukijärjestelmät). |
| PUE | Power Usage Effectiveness = koko datakeskuksen sähkö / IT-kuorman sähkö. Mitä lähempänä 1,0, sitä parempi. |
| WUE | Water Usage Effectiveness = vedenkulutus suhteessa IT-kuorman energiankäyttöön (mittaritapa vaihtelee rajauksesta). |
| CUE | Carbon Usage Effectiveness = hiilidioksidipäästöt suhteessa IT-kuorman energiankäyttöön (kgCO₂e/IT-kWh). |
| Historiadata | Aiemmista käyttöjaksoista kerätty data kuormista, resursseista ja suorituskyvystä mitoituksen ja ennusteen pohjaksi. |
| Työpyyntö (job) | Kuormayksikkö (esim. batch-ajo, laskentatehtävä, palvelupyyntö), jonka resurssitarve voidaan mallintaa. |
| Kuorman tyypitys (workload characterization) | Kuorman ryhmittely työtyypeiksi (esim. klusterointi), jotta resursseja voidaan mitoittaa/ohjata. |
| Klusterointi | Menetelmä, jolla havaintoja ryhmitellään samankaltaisuuden mukaan (esim. työtyypit). |
| k-means | Yleinen klusterointialgoritmi, jossa havaintoja jaetaan k ryhmään etäisyysperiaatteella. |
| Kuormaennuste (workload prediction) | Tulevien kuormien määrän/luonteen ennustaminen aikasarjamalleilla. |
| ARIMA | Aikasarjamalli, jota käytetään trendin ja kausivaihtelun ennustamiseen (esim. kuorma per aikaväli). |
| Resurssiprofiili | Työtyypin tyypillinen CPU-, muisti-, I/O- ja aikavaade (sekä mahdollinen prioriteetti/SLA). |
| SLA | Service Level Agreement: sovittu palvelutaso (esim. vasteaika, saatavuus), joka ohjaa mitoitusta. |
| SLO | Service Level Objective: mitattava palvelutasotavoite, joka määrittää tavoitetason yhdelle tai useammalle mittarille ja jonka pohjalta palvelua operoidaan ja mitoitetaan (kapasiteetti, varmistus, häiriöbudjetti). |
| Deadline | Aikaraja, johon mennessä työ on valmistuttava. |
| Job–server mapping | Sääntö/kuvaus siitä, mille palvelintyypeille tietty työ voidaan sijoittaa (kelpoisuus). |
| CPU | Prosessoriresurssi (laskentakapasiteetti), usein keskeinen rajoite työkuormien sijoittelussa. |
| Muisti (RAM) | Käyttömuisti; rajoite erityisesti datakeskeisille/virtuaalikuormille. |
| Kapasiteettisuunnittelu | Päätöksenteko siitä, kuinka paljon palvelimia/infra-kapasiteettia tarvitaan kuormaan ja SLA:han nähden. |
| ILP | Integer Linear Programming: kokonaislukusuunnittelu, jolla voidaan muotoilla mm. mitoitus- ja sijoitteluongelmia. |
| Bin packing | Pakkausongelma: kohteet (työt) sijoitetaan “laatikoihin” (palvelimet) kapasiteettirajoitteilla. |
| NP-vaikea | Ongelmaluokka, jossa täsmäratkaisu voi kasvaa nopeasti laskennallisesti vaikeaksi. |
| Heuristiikka | Käytännön “hyvä riittävä” -ratkaisutapa, joka ei takaa optimaalista ratkaisua mutta toimii tehokkaasti. |
| First-fit | Heuristiikka: sijoita kohde ensimmäiseen kelpaavaan “laatikkoon” (esim. palvelimeen, jossa riittää kapasiteetti). |
| Tehomalli | Malli, joka arvioi palvelimen tehonkulutusta kuormituksen funktiona (aktiivinen + peruskulutus). |
| Energian proportionalisuus | Tavoite, että laitteen energiankulutus skaalautuu lähelle lineaarisesti kuorman mukana. |
| Tyhjäkäyntiteho (idle power) | Teho, jonka palvelin kuluttaa lähes ilman kuormaa; keskeinen syy vajaakuorman energiahukkaan. |
| Ylikapasitointi (over-provisioning) | Kapasiteetin mitoittaminen selvästi yli keskimääräisen tarpeen (huiput/varmuus), joka laskee käyttöastetta. |
| Käyttöaste | Kuinka suuri osa IT-kapasiteetista on käytössä (esim. CPU-utilisaatio); vaikuttaa energiatehokkuuteen. |
| Hyperskaala | Suuret pilvitoimijat, joilla on erittäin suuret konesalit ja pitkälle automatisoitu operointi. |
| Virtualisointi | Useita virtuaalikoneita/kontteja ajetaan samassa fyysisessä palvelimessa eristetysti. |
| Konsolidointi | Kuormien kokoaminen harvemmille fyysisille palvelimille käyttöasteen nostamiseksi ja tyhjäkäyntihävikin pienentämiseksi. |
| DVFS | Dynamic Voltage and Frequency Scaling: prosessorin jännitteen/taajuuden säätö kuorman mukaan energiansäästöön. |
| Lepotila / sleep state | Komponentin tai järjestelmän matalatehotila, kun kapasiteettia ei tarvita hetkellisesti. |
| Power capping | Tehoraja, jolla IT-laitteiden kulutusta rajoitetaan (esim. verkon/UPS:n rajoitteet, kustannusoptimointi). |
| Sähkönsyöttöketju | Muuntajat + UPS + PDU + kaapelointi + IT-kuorma; häviöt syntyvät jokaisessa muunnos-/jakeluvaiheessa. |
| Muuntohäviöt | Tehoelektroniikan ja muuntajien aiheuttamat häviöt (lämpönä), jotka heikentävät ketjun hyötysuhdetta. |
| UPS | Uninterruptible Power Supply: keskeytymätön virransyöttö, joka ylläpitää kuormaa katkoksessa siirtymän ajan. |
| BESS | Battery Energy Storage System: akkuvarasto ohjaus-, suojaus- ja tehoelektroniikkakomponenteilla. |
| Omakulutus (perushäviöt) | Kuormasta riippumaton kulutus (ohjaus, valvonta, lämpöhallinta), joka korostuu osakuormilla. |
| Peak shaving | Kuormahuippujen leikkaaminen varastolla tai ohjauksella, jotta huipputehoa ja kustannuksia pienennetään. |
| Power quality | Sähkönlaatu: jännite-/taajuuspoikkeamat, transientit jne.; UPS/superkondensaattorit voivat tukea. |
| Superkondensaattori | Lyhytkestoiseen tehotukeen sopiva varasto (nopea vaste, pieni energiasisältö). |
| Vauhtipyörävarasto | Mekaaninen varasto, joka soveltuu sekunti–minuutti -tason UPS-tukeen (nopea vaste). |
| Redundanssi (N+1, 2N) | Varmistusperiaate: ylimääräinen kapasiteetti (N+1) tai kaksinkertainen järjestelmä (2N) saatavuuden parantamiseksi. |
| Osakuorma | Tilanne, jossa laite käy selvästi alle nimelliskuorman; suhteelliset häviöt kasvavat usein. |
| PDU | Power Distribution Unit: sähkönjakeluyksikkö (usein räkkikohtainen), jakaa syötön IT-laitteille. |
| BMS | Building Management System: rakennusautomaatio (HVAC, energiavirrat, hälytykset). |
| DCIM | Data Center Infrastructure Management: datakeskuksen infrastruktuurin valvonta/johtaminen (energia, kapasiteetti, ympäristö). |
| Free cooling | Vapaajäähdytys: ulkoilman/ulkoveden hyödyntäminen jäähdytyksessä ilman kompressorityötä suurimman osan ajasta. |
| Hot aisle / cold aisle | Kuuma–kylmäkäytäväjärjestely, jolla erotetaan poisto- ja tuloilma ja vähennetään sekoittumista. |
| Ohivirtaus (bypass) | Ilmavirta, joka kiertää kuorman ohi (esim. vuotokohdista) ja heikentää jäähdytyksen tehokkuutta. |
| Nestejäähdytys (direct-to-chip) | Lämpö siirretään nesteeseen lähellä komponenttia, mikä vähentää puhallinsähköä ja parantaa lämmön talteenottoa. |
| Immersiojäähdytys | Palvelinkomponentit upotetaan sähköä johtamattomaan nesteeseen tehokasta lämmönsiirtoa varten. |
| Commissioning | Käyttöönoton testaus- ja todentamisprosessi (toiminnallisuus + suorituskyky + mittarointi). |
| M&V | Measurement & Verification: mittauksen ja todentamisen käytännöt (rajaukset, tarkkuus, datapolut). |
| BoD (Basis of Design) | Suunnittelun perusteludokumentti: miksi ratkaisut valittiin, miten tavoitteet (mm. KPI:t) saavutetaan. |
| QA/QC | Quality Assurance/Quality Control: laadunvarmistus ja tarkastus (asennus, mittarit, testit). |
| Stage-gate | Projektiporttimalli: eteneminen vaiheittain tarkastuspisteiden kautta (vaatimukset, luvat, investointipäätös). |
| As-built | Toteumadokumentit, jotka kuvaavat lopullisen rakennetun ratkaisun (välttämätön operoinnille). |
| Hukkalämpö | IT- ja infrastruktuurihäviöistä syntyvä lämpö, joka voidaan talteenottaa ja hyödyntää (esim. kaukolämpö). |
| Kaukolämpöliityntä | Datakeskuksen lämmönsyöttö paikalliseen kaukolämpöverkkoon; edellyttää lämpötilatasoa ja sopimusmallia. |
| PPA | Power Purchase Agreement: pitkäaikainen sähkönhankintasopimus, usein uusiutuvasta tuotannosta. |
| Alkuperätakuu | Sertifikaatti sähkön alkuperästä (esim. uusiutuva); tärkeä raportoinnissa mutta ei yksin ratkaise verkon fyysistä tuotantorakennetta. |
| Mikroverkko (microgrid) | Paikallinen sähköjärjestelmä, joka voi ohjata tuotantoa/kuormaa/varastoa yhdessä (voi toimia myös irti pääverkosta). |
| LCA | Life Cycle Assessment: elinkaariarviointi, jossa tarkastellaan ympäristövaikutuksia valmistuksesta käyttöön ja loppukäsittelyyn. |
| E-jäte (e-waste) | Sähkö- ja elektroniikkaromu; keskeinen kiertotalous- ja vastuullisuuskysymys datakeskuksen elinkaaressa. |
| Media sanitization | Tallennusmedian tietoturvallinen tyhjennys/hävittäminen (esim. NIST-ohjeiden mukaan). |
| BAT | Best Available Techniques: parhaat käytettävissä olevat tekniikat; viitekehys luvituksessa ja ympäristövaatimuksissa. |
| BREF | BAT Reference Document: BAT-viiteasiakirjat, jotka kokoavat alan parhaat tekniikat ja vertailutasot. |
| IED | Industrial Emissions Directive: EU:n teollisuuspäästödirektiivi; voi koskea datakeskusta tapauskohtaisesti. |
| DCN | Data Center Network: datakeskuksen sisäinen verkko (topologia, linkit, kytkimet), jolla on myös energiajalanjälki. |




# Liite A: Esimerkkimittaripistekartta (PUE/CUE/WUE + häviöiden paikannus)

## A1. Sähkönjakeluketjun energianmittaus 

**Tavoite:** erottaa kolme asiaa, jotta energiatehokkuutta voidaan parantaa järkevästi:
1) **IT-laitteiden energiankulutus** (palvelimet / storage / verkko)  
2) **Sähköketjun häviöt** (UPS + jakelu)  
3) **Muu konesalin energiankulutus** (jäähdytys, pumput, puhaltimet, valaistus jne.)

Jos nämä menevät “yhdeksi luvuksi”, et näe mistä PUE paranee tai huononee.

---

### 1) Mitä sähkönjakeluketjussa tapahtuu 

```text
Jakeluverkko (tuleva sähkö)
  |
  | [M1] Päämittaus: paljonko koko kohde kuluttaa sähköenergiaa
  v
Pääkeskus (konesalin pääjakelu)
  |
  | [M2] IT-syötön mittaus: paljonko sähköenergiaa ohjautuu konesalin kriittiseen syöttöön
  v
UPS (keskeytymätön virransyöttö)
  |  [M3] UPS sisään: UPS:lle tuleva sähkönsyöttö
  |  [M4] UPS ulos: UPS:ltä IT-saliin lähtevä sähkönyöttö
  |       -> UPS-häviö ≈ (M3 − M4)
  v
Sähkönjakelu IT-saliin (alue-/salitaso)
  |
  | [M5] Alue-/salimittaus: paljonko sähköenergiaa menee tiettyyn saliin tai alueeseen
  v
Räkit / räkkijakelu (PDU)
  |
  | [M6] IT-mittaus: räkki- tai ryhmätaso (paras “IT-sähköenergiakuorman” arvio)
  v
IT-laitteet (server / storage / network)

```

**Hyvä nyrkkisääntö:** jos et saa erotettua **UPS-häviötä** ja **jäähdytyksen kulutusta**, et pysty perustelemaan, missä PUE:n parannus oikeasti syntyy.

---

## A2. Mittaripisteet taulukkona (minimi → hyvä → erinomainen)

| ID | Sijainti / rajapinta | Mitä mitataan | Miksi mitataan | Vähimmäistaso |
|---|---|---|---|---|
| M1 | Liittymä / utility meter | kWh, kW, PF | Kokonaiskulutus (Facility Energy) | **Pakollinen** |
| M2 | MSB-lähdöt (kriittiset) | kW/kWh per lähtö | Erottaa suuret kulutuskorit (IT vs MEP) | Suositus |
| M3 | UPS input | kW/kWh | UPS-häviöiden laskenta | Suositus |
| M4 | UPS output | kW/kWh | IT-syötön mittaus (IT-lähempänä) | **Pakollinen PUE-tarkkuudelle** |
| M5 | PDU/RPP | kW/kWh per sali/alue | Häviöiden paikannus vyöhykkeittäin | Hyvä taso |
| M6 | Räkkimittaus | kW/kWh per räkki | Kuorman hallinta, kapasiteetti, laskutus | Hyvä/erinomainen |

---

## A3. Jäähdytys- ja lämpömittaukset (jotta “PUE:n toinen puoli” ei ole arvaus)

| ID | Sijainti | Mitä mitataan | Miksi mitataan |
|---|---|---|---|
| C1 | Jäähdytyskoneikko / chiller | kW/kWh | Jäähdytyksen suurin sähköerä (jos ei free cooling) |
| C2 | Pumput (prim/sek) | kW/kWh + virtaus | Pumpun osuus ja optimointi (Δp, virtaus) |
| C3 | CRAH/CRAC puhaltimet | kW/kWh | Ilmansiirron energiahukka / ohivirtaus |
| C4 | Ulkoilma/free cooling -laitteet | kW/kWh | Todentaa “Suomi-edun” realisoituminen |
| T1 | Tuloilma palvelimille | °C, RH | Lämpötilasäätö ja riskien hallinta |
| T2 | Paluuilma | °C, RH | Hot/cold aisle -toimivuus, sekoittuminen |
| H1 | LTO-lämmönvaihdin (jos käytössä) | lämpöteho (kWth), energiamäärä (MWhth) | Hukkalämmön hyöty, raportointi |

> Huom: Lämpöenergian mittaus kannattaa tehdä siten, että saat sekä **lämpötehon (kWth)** että **energiamäärän (MWhth)** raportointiin ja sopimuksiin.

---

## A4. PUE/CUE/WUE – mitä tarvitset laskentaan (käytännön minimi)

- **PUE** = (Facility Energy) / (IT Energy)  
  - Facility Energy: yleensä **M1**  
  - IT Energy: vähintään **M4** (tai M6 aggregoituna)

- **CUE** = (CO₂e) / (IT Energy)  
  - tarvitset sähkön **päästökertoimen** + IT Energy (M4/M6)

- **WUE** (jos relevantti) = (vesi) / (IT Energy)  
  - tarvitset kokonaisveden + jäähdytysvesien erottelun

---

# Liite B: Päätöspuu hukkalämmön hyödyntämiseen (Suomi-konteksti)

## B1. Päätöspuu (nopea “go/no-go”)

**Lähtötieto (pakollinen):**
- IT-teho (kW), arvio PUE:sta, arvio **talteenotettavasta lämpötehosta** (kWth)
- lämpötilataso (esim. ilma 25–35°C / vesi 30–60°C / “korkea” 60–80°C)
- etäisyys mahdolliseen lämpöasiakkaaseen / kaukolämpöön (km)

---

1. Onko lämmölle vastaanottaja lähellä?

   * Ei -> Hyödynnä sisäisesti (toimistot, prosessit) tai suunnittele myöhempi varaus (putkivaraukset).
   * Kyllä -> 2

2. Onko lämpötilataso riittävä suoraan vastaanottajalle?

   * Kyllä (esim. paikallinen matalalämpöverkko / prosessi) -> 4
   * Ei -> 3

3. Voidaanko lämpöpumpulla nostaa taso taloudellisesti?

   * Laske COP-arvio ja sähkön lisäkulutus
   * Jos talous ok -> 4
   * Jos ei -> suunnittele “valmius” (LTO + liityntä) ja palaa myöhemmin

4. Onko käyttöprofiili yhteensopiva (lämpöä tarvitaan silloin kun sitä syntyy)?

   * Kyllä -> 5
   * Ei -> harkitse: (a) lämpövarasto (TES), (b) sopimus joustosta, (c) osittainen hyödyntäminen

5. Toteutuskelpoisuus:

   * Putkireitti, lämmönvaihdin, mittaus (MWhth), sopimukset, luvitus
   * Jos ok -> Toteuta + mittaroi (H1)

---

---

## B2. Mitä “vaiheen ohittaminen” tyypillisesti maksaa (käytännön oppi)

- **Jos vastaanottaja kartoitellaan vasta rakentamisen jälkeen:**  
  joudut vetämään putkireittejä “valmiiseen” ympäristöön → lisätyö, käyttökatkot, ja usein heikompi hyötysuhde.

- **Jos lämpötilatasoa ei suunnitella (air vs liquid cooling):**  
  saatat päätyä lämpöön, jonka hyödyntäminen vaatii aina lämpöpumpun → jatkuva lisäsähkö ja pienempi nettovaikutus.

- **Jos mittaus (MWhth) puuttuu:**  
  hukkalämmön “vihreä hyöty” jää väitteeksi → vaikea perustella investointia, vaikea raportoida.

---

## B3. Mini-esimerkkilasku (suuruusluokat lukijalle)

**Oletus:** IT-kuorma 1 MW, talteenotettava osuus 80%, käyttöaika 8 000 h/a.

- Talteenotettava lämpöenergia ≈ 1 MW × 0.8 × 8 000 h = **6 400 MWhth/a**
- Jos tämä korvaa kaukolämpöä, vaikutus riippuu paikallisesta päästökertoimesta ja sopimuksesta.
- Oppaan kannalta tärkein oppi: **jo “pienen” MW-luokan datakeskuksessa hukkalämpö on GWh-luokkaa vuodessa** → kannattaa ainakin tehdä vastaanottajakartoitus ja varaukset.

---


- Päätekstissä viittaa näin:
  - “Mittauspisteiden minimirunko on esitetty Liitteessä A.”
  - “Hukkalämmön hyödyntämisen päätöspuu on esitetty Liitteessä B.”
 
---




