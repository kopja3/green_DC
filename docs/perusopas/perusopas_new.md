

### P1.1 Miksi perusopas?

Tämä perusopas tukee vihreän datakeskuksen suunnittelua ja toteutusta Suomessa. Opas jäsentää keskeiset päätökset vaiheisiin ja kytkee ne mitattaviin suureisiin: **energia (E), teho (P), kapasiteetti (C)** ja **palvelutaso (SLA)** (Uddin & Rahman, 2012; Geng, 2015; Jin et al., 2016). Keskeinen periaate on, että jokainen “vihreyttä” koskeva väite voidaan palauttaa **mittausrajaan**, **mittauspisteisiin** ja **laskentasääntöön**.

Opas etenee seuraavasti:

* **Luku 2: Miksi datakeskus rakennetaan ja miten sijainti valitaan**
  Sijainnin reunaehdot: sähkö, verkko, viive, jäähdytys sekä hukkalämpöliitynnät.

* **Luku 3: Vihreän datakeskuksen peruselementit ja periaatteet**
  Osa-alueet ja käsitteet, joilla vihreyttä tarkastellaan; mittausrajat ja arvioinnin periaatteet.

* **Luku 4: Datakeskuksen elinkaaren vaiheet**
  Suunnittelu, rakentaminen, käyttö ja käytöstäpoisto; data- ja materiaalivirrat.

* **Luku 5: Datakeskuksen toiminta vaiheittain**
  Kuorma ja palvelutaso → kapasiteettisuunnittelu → IT-teho ajan funktiona → sähkö- ja jäähdytysinfrastruktuurin mitoitus.

* **Luku 6: Energian kulutus ja uudelleenkäyttö**
  Kulutuserät, jäähdytyksen sähkönkulutus, hukkalämmön talteenotto, rajapinnat ja mittaustieto.

* **Luku 7: Energiatehokkuuden mittaaminen**
  EN/ISO/IEC 30134 -mittarit ja mittauspisteet; mittarikortit (PUE, REF, ERF, CER, CUE, WUE).

Oppaan merkinnät ja mitoitusketjun symbolit esitellään kohdassa **P1.4**.

---

### P1.2 Mikä on vihreä datakeskus?

Tässä oppaassa **vihreä datakeskus** tarkoittaa datakeskusta, jossa suunnittelu ja operointi sidotaan **energian käytön mittaamiseen**, **energiatehokkuusmittareihin** ja **päästöintensiteetin raportointiin** (Uddin & Rahman, 2012; Jin et al., 2016; Geng, 2015). “Vihreys” ei ole yksittäinen tekninen ratkaisu, vaan päätösten ketju, jonka vaikutus voidaan todentaa datasta.

Vihreä datakeskus tarkastellaan seuraavina osa-alueina:

* **Kuorma ja kapasiteetti:** työkuorman kuvaus, kapasiteetin mitoitus ja IT-tehon vaihtelu ajassa.
* **Sähkönsyöttö ja varmistus:** sähköliittymä, jakelu, UPS/varavoima ja häviöt.
* **Sähkön alkuperä ja päästöt:** hankintatapa, todentaminen ja päästökertoimet raportointiin.
* **Jäähdytys:** jäähdytysarkkitehtuuri ja jäähdytyksen sähkönkulutus suhteessa IT-tehoon.
* **Hukkalämpö:** talteenotto, mittaus ja luovutusrajapinta.
* **Elinkaaren loppu:** käytöstäpoisto, tietojen hävittäminen ja materiaalivirrat.

Osa-alueiden päätökset kuvataan kohdassa **P1.8**, ja tekninen toteutus avataan luvussa **3**.

---

### P1.3 Miten opasta käytetään?

Opas on kirjoitettu päätöksenteon ja dokumentoinnin tueksi. Käytä sitä niin, että etenet aina **kysymyksestä päätökseen** ja päätöksestä **mitattaviin lähtötietoihin**.

1. **Määritä lähtötiedot ja rajaukset.**
   Kirjaa työkuorman ja palvelutason vaatimukset sekä mittausrajat (mistä kokonaisenergia mitataan ja mistä IT-energia rajataan).

2. **Johda mitoitusketju.**
   Johda työkuormasta kapasiteetti ja IT-tehon vaihtelu ajassa, ja mitoita niiden perusteella sähköliittymä, jakelu, varmistus ja jäähdytys (merkinnät ja suureet kohdassa **P1.4**).

3. **Valitse mittarit ja todentaminen.**
   Valitse energiatehokkuus- ja päästömittarit, määritä mittauspisteet ja dokumentoi sähkön alkuperän todentaminen sekä päästökertoimet raportointia varten.

Kun toteutus on käynnissä, käytä toimintamallia: **mittaa → analysoi → muutos → todenna → vakioi**.

---

## P1.4 Datakeskuksen sähkö- ja jäähdytysinfrastruktuurin tehomitoitusketju

Tässä kohdassa määritellään oppaan kannalta keskeiset suureet ja merkinnät sekä esitetään tehomitoituksen “ketju”: miten työkuormasta ja palvelutasovaatimuksista johdetaan IT-teho ja edelleen sähkö- ja jäähdytysinfrastruktuurin mitoitus (Geng, 2015; Wang et al., 2020).

### Perustermit ja yksiköt

- **Teho, P**: hetkellinen sähköteho. Yksikkö **W**, **kW**, **MW**.  
- **Energia, E**: teho aikajaksolla. Yksikkö **Wh**, **kWh**, **MWh**, **GWh** (esim. *kWh = kW × h*).  

- **IT-työkuorma, L(t)**: datakeskukseen saapuvien palvelu- ja työpyyntöjen määrä ja ominaisuudet ajan funktiona (esim. pyyntöä/s, transaktiota/s, jobeja/eräajoja, datavirtoja).  
- **Palvelutasovaatimus (SLA / deadline / saatavuus)**: ehto, jonka puitteissa pyyntö käsitellään (esim. vasteaika, määräaika, saatavuustaso) (Wang et al., 2020).

- **Laskentakapasiteetti (IT-kapasiteetti), C**: IT-resurssit, joilla **L(t)** suoritetaan sovituilla palvelutasoilla (palvelimet, CPU/GPU, muisti, tallennus, verkko). Kapasiteetti on kapasiteettisuunnittelun tulos (Wang et al., 2020).  
  - **Asennettu kapasiteetti, C_inst**: hankittu ja asennettu resurssipooli (teoreettinen enimmäistaso).  
  - **Aktiivinen kapasiteetti, C_act(t)**: se osa resurssipoolista, joka pidetään käytössä ajanhetkellä *t* (aktiiviset palvelimet ja niiden resurssit).  
  - **Varakapasiteetti, C_res**: kapasiteetti, jota pidetään käytettävissä kuormahuippujen, ennusteen epävarmuuden tai vikatilanteiden varalta (SLA ja varmistusperiaate) (Whitney & Delforge, 2014; Wang et al., 2020).

- **IT-teho, P_IT(t)**: IT-laitteiden (palvelimet, tallennus, verkko) ottama sähköteho ajanhetkellä *t*. Yksikkö **kW(IT)**.  

- **Lämpökuorma / jäähdytyskuorma, Q_th(t)**: poistettava lämpöteho tilasta tai jäähdytyspiiristä. Yksikkö **kW(th)**. Käytännön mitoituksessa **Q_th(t)** määräytyy IT-tehon ja muiden sähkökuormien (ml. sähköketjun häviöt) perusteella (Geng, 2015).  

- **Jäähdytyksen sähköteho, P_cool(t)**: jäähdytysjärjestelmän (esim. chillerit, pumput, puhaltimet, CRAH/CRAC) ottama sähköteho. Yksikkö **kW(e)**.  
  > Huomio: **P_cool(t)** (sähköteho) ja **Q_th(t)** (poistettava lämpöteho) ovat eri suureita (Geng, 2015).

### Tehomitoitusketju (tekstimuotoinen “kuva”)

**Tehomitoitusketju** tarkoittaa päätöksentekoketjua, jossa IT-työkuorman **L(t)** ja palvelutasovaatimusten (SLA/deadline sekä saatavuus) perusteella johdetaan vaiheittain datakeskuksen sähkö- ja jäähdytysinfrastruktuurin mitoitus (ml. sähköliittymä, UPS/varavoima, jakelu ja jäähdytysjärjestelmät) (Geng, 2015; Wang et al., 2020).

Ketju esitetään seuraavasti:

**L(t) + (SLA/deadline, saatavuus) → C_act(t) (+ C_res) → P_IT(t) → sähkö- ja jäähdytysinfrastruktuurin mitoitus**

#### Ketjun tulkinta vaiheittain

1. **L(t) + SLA/deadline (+ saatavuus) → C_act(t) (+ C_res)**  
   Kuorman määrä ja vaihtelu sekä palvelutasoehdot määrittävät, kuinka suuri osa **C_inst**:stä pidetään aktiivisena (**C_act(t)**) ja kuinka paljon kapasiteettia pidetään varalla (**C_res**) (Whitney & Delforge, 2014; Wang et al., 2020).

2. **C_act(t) → P_IT(t)**  
   Aktiivisten resurssien määrä ja kuormitusaste muodostavat IT-tehoprofiilin **P_IT(t)**, joka toimii sähkö- ja jäähdytysjärjestelmien mitoituksen lähtötietona (Geng, 2015; Wang et al., 2020).

3. **P_IT(t) → infrastruktuurin mitoitus**  
   IT-teho ja siihen liittyvät häviöt määrittävät sähköketjun mitoitustehoja (liittymä, UPS, jakelu) sekä lämpökuorman **Q_th(t)**, jonka perusteella jäähdytysjärjestelmät mitoitetaan (Geng, 2015).

### Varmistusperiaate (N, N+1, 2N)

**Varmistusperiaate** (esim. **N+1**, **2N**) tarkoittaa, että infrastruktuuri mitoitetaan siten, että kuorma voidaan ylläpitää myös yksittäisen komponentin vikaantuessa. Tämä näkyy sekä asennettuna infrastruktuurikapasiteettina että osakuormalla toimivien laitteiden hyötysuhteina (Geng, 2015; Whitney & Delforge, 2014).

### Huomio (vihreä tarkastelu)

Tässä oppaassa sama tehomitoitusketju säilyy, mutta hankkeessa määritetään lisäksi:

- sähkön alkuperän todentaminen,
- energian käytön mittausrajat, ja
- hukkalämmön talteenoton ja hyötykäytön rajapinnat (Jin et al., 2016; Uddin & Rahman, 2012).

**Mittausrajalla** tarkoitetaan, mistä pisteestä kokonaisenergia mitataan (esim. sähköliittymä / pääkeskus) ja mistä pisteestä IT-energia mitataan (esim. UPS/PDU-lähdöt tai räkki-/PDU-mittaus). Rajaus määrittää, mitkä häviöt ja kuormat sisältyvät energiatehokkuuslukuihin (esim. PUE) (Jin et al., 2016; Uddin & Rahman, 2012).

---

## P1.5 Tausta: perinteinen kapasiteetti- ja tehomitoitus datakeskuksessa (tiivis)

P1.4 määritteli tehomitoitusketjun muodossa:

**L(t) + (SLA/deadline, saatavuus) → C_act(t) (+ C_res) → P_IT(t) → sähkö- ja jäähdytysinfrastruktuurin mitoitus** (Geng, 2015; Wang et al., 2020).

Tässä kappaleessa tarkennetaan ketjun alkupäätä: miten saapuvista työpyynnöistä muodostetaan työkuorman kuvaus **L(t)** ja miten sen perusteella tehdään kapasiteettisuunnittelun päätökset (aktiivinen kapasiteetti **C_act(t)** ja varakapasiteetti **C_res**), joista edelleen johdetaan IT-tehoprofiili **P_IT(t)** (Wang et al., 2020).

### Keskeiset termit (katso myös sanasto, s. X)

- **Työpyyntö (job):** yksittäinen suoritettava tehtävä tai pyyntö, jolle määritetään resurssitarpeet ja aikavaatimus (Wang et al., 2020).
- **IT-työkuorma L(t) (workload):** työpyyntöjen määrä ja ominaisuudet ajan funktiona sekä kuorman vaihtelu ja huiput (Wang et al., 2020).
- **Työtyypitys (workload characterization):** työpyyntöjen ryhmittely työtyypeiksi ja työtyyppikohtaisten resurssiprofiilien kuvaus (Wang et al., 2020).
- **Kuormaennuste (workload prediction):** työpyyntöjen määrän (ja tarvittaessa työtyyppijakauman) ennustaminen tuleville aikajaksoille historiadatan perusteella (Wang et al., 2020).
- **Kapasiteettisuunnittelu:** päätös siitä, mitä kapasiteettia pidetään käytössä **C_act(t)**, mitä varalla **C_res**, ja miten työpyynnöt sijoitetaan niin, että resurssirajat ja SLA/deadline täyttyvät (Wang et al., 2020).

### Lähtötieto perinteisessä mitoituksessa

Perinteinen mitoitus nojaa usein historiadataan ja siitä johdettuun kuormakuvaan. Käytännössä erotetaan kaksi vaihetta:

1. **Työkuorman tyypittäminen** (työtyypit ja niiden resurssiprofiilit)
2. **Kuorman ennustaminen** (työpyyntöjen määrä ja vaihtelu tuleville jaksoille) (Wang et al., 2020)

Kun työtyypit ja palvelutasovaatimukset on kuvattu, kapasiteettitarve johdetaan resurssivaatimuksista ja aikarajoitteista (SLA/deadline) sekä siitä, millä palvelin-/resurssityypeillä työ voidaan suorittaa (job–server mapping) (Wang et al., 2020). Käytännön ratkaisuissa mitoitus tehdään usein optimointia ja heuristiikkoja hyödyntäen, koska ongelma kasvaa nopeasti hyvin suureksi (Garey & Johnson, 1979; Wang et al., 2020).

### Vaihtoehtoinen lähtötieto: sovellus- ja alustataso

Toinen tyypillinen lähestymistapa on mitoittaa kapasiteettia sovellus- ja palveluarkkitehtuurin sekä kasvuennusteiden perusteella ja huomioida myös siirtymävaiheet (refresh capacity) (Geng, 2015). Sähkötehon mitoituksessa erotetaan lisäksi kuorman sähköiset ominaisuudet (W/VA/PF), koska ne vaikuttavat verkosta ja varavoimasta tarvittavaan kapasiteettiin (Geng, 2015).

### Yhteenveto

Perinteisessä mitoituksessa lähtötieto tulee tyypillisesti joko (a) sovellus- ja alustatasolta tai (b) kuormadataan perustuvasta kuormakuvasta ja ennusteesta. Molemmissa tapauksissa tavoitteena on johtaa **P_IT(t)**, jonka perusteella sähkö- ja jäähdytysinfrastruktuuri mitoitetaan (Geng, 2015; Wang et al., 2020).

---

## P1.6 Käyttöaste ja IT-tehon kuormariippuvuus (johdantotaso)

Käyttöaste vaikuttaa energiankulutukseen, koska IT-laitteiden sähköteho muodostuu tyypillisesti kahdesta osasta:

1. **Perustehosta**, joka ei alene samassa suhteessa kuorman kanssa, ja  
2. **Kuormaan sidotusta osasta**, joka kasvaa kuorman kasvaessa (Barroso & Hölzle, 2007; Whitney & Delforge, 2014).

Katsauksissa perinteisten yritysdatasalien käyttöaste on raportoitu usein matalaksi verrattuna hyperskaalaan, jossa kuormia voidaan konsolidoida ja ohjata suuremmassa resurssipoolissa (Whitney & Delforge, 2014). Käyttöastetta laskevat erityisesti:

- kuorman vaihtelu ja ennusteen epävarmuus, sekä
- palvelutasovaatimukset (SLA/deadline), joiden vuoksi kapasiteettia pidetään varalla **C_res** (Whitney & Delforge, 2014; Wang et al., 2020).

Lisäksi saatavuusvaatimukset näkyvät infrastruktuurissa varmistusratkaisuina (esim. N+1, 2N), jotka lisäävät valmiina pidettävää laite- ja järjestelmäkantaa sekä niiden aiheuttamaa perustason sähkönkulutusta (Whitney & Delforge, 2014).

Palvelinten sähkönkulutus ei historiallisesti ole ollut täysin energiaproportionaalista: tyhjäkäynnillä ja matalalla käyttöasteella kulutus ei alene samassa suhteessa kuin kuormitus (Barroso & Hölzle, 2007; Whitney & Delforge, 2014). Tämän vuoksi kapasiteettisuunnittelu ja kuormanohjaus vaikuttavat suoraan datakeskuksen energiankulutukseen ja siitä johdettuihin päästöihin (Jin et al., 2016; Whitney & Delforge, 2014).

---

## P1.7 Kansainvälinen kehitys ja Suomen reunaehdot

Datakeskuksia rakennetaan digitalisaation, pilvipalvelujen ja verkottuneiden sovellusten IT-kapasiteetin (laskenta-, tallennus- ja verkkokapasiteetti) toteuttamiseksi. Samalla hajautettuja ja teknisesti vanhentuneita ympäristöjä korvataan keskistetyillä ratkaisuilla, joissa kapasiteettia ja operointia voidaan ohjata järjestelmätasolla (Jin et al., 2016; Shehabi et al., 2016). Datakeskusten osuus maailman sähkönkulutuksesta on ollut suuruusluokkaa noin yksi prosentti, vaikka laskentakapasiteetti ja datamäärät ovat kasvaneet (Masanet et al., 2020). Skenaarioissa on arvioitu, että ilman lisätoimia ICT-sektorin sähkönkäyttö voi kasvaa useisiin prosentteihin maailman kokonaiskulutuksesta, jos liikennemäärät ja kuormat jatkavat kasvuaan (Andrae & Edler, 2015). Uudemmissa tarkasteluissa on nostettu esiin myös suuritehoisen laskennan ja generatiivisen tekoälyn kuormien vaikutus energiatiheyksiin ja käyttöönoton nopeuteen (Sabree, 2025; Masanet et al., 2020).

Datakeskuksen käyttöaikaisia kasvihuonekaasupäästöjä voidaan arvioida kertomalla datakeskuksen käyttämä sähköenergia (kWh) käytetyn sähkön päästökertoimella (kgCO₂e/kWh). Tämä kattaa sähkönkulutukseen liittyvän osuuden; laajemmassa hiilijalanjälkirajauksessa voidaan lisäksi huomioida mm. varavoiman polttoaine, jäähdytyksen kylmäainepäästöt sekä laitteiden ja rakennuksen elinkaaren aikaiset päästöt (Jin et al., 2016; Sabree, 2025).

---

## P1.8 Vihreän datakeskuksen elementit ja päätöspisteet

Tässä perusoppaassa vihreä datakeskus jäsennetään **päätöspisteiksi**. Päätökset esitetään muodossa **päätös → tuotos → luku**, jotta etenemisjärjestys ja kunkin vaiheen tuotokset löytyvät yhdestä paikasta. Osa-alueet on kuvattu kohdassa **P1.2** ja mitoitusketjun merkinnät kohdassa **P1.4**.

Kirjallisuudessa vihreä datakeskus kytkee IT-, sähkö- ja jäähdytysjärjestelmät energian ja ympäristövaikutusten mittaamiseen sekä seurantaan, ja tarkastelu esitetään tyypillisesti mittareina ja osa-alueina (kuorma–kapasiteetti, sähköketju, jäähdytys, hukkalämpö, todentaminen) (Uddin & Rahman, 2012; Jin et al., 2016; Geng, 2015; Wang et al., 2020; Barroso & Hölzle, 2007).

Tämä perusopas tuo samaan kokonaisuuteen **päätös→tuotos→luku**-rakenteen, jotta mitoitusketju ja mittausrajat voidaan viedä suunnittelusta toteutukseen ja raportointiin ilman, että lähtötietoja kootaan useista eri kohdista.

### Päätökset (päätös → tuotos → luku)

- **Sijainti** → sähkö-, verkko- ja liityntäehdot (jäähdytys ja hukkalämpö), viive- ja saatavuusrajat → **Luku 2**
- **Työkuorma ja palvelutaso (SLA)** → kuormakuvaus *L(t)* ja palvelutasorajat (vasteajat/saatavuus/deadline) → **Luku 5** (Wang et al., 2020)
- **Kapasiteetti** → *C_inst*, *C_act(t)* ja *C_res(t)* (asennettu, käytössä pidettävä, varalla pidettävä) → **Luku 5** (Wang et al., 2020)
- **IT-tehoprofiili** → *P_IT(t)* (IT-teho ajan funktiona; huiput ja niiden kesto) → **Luku 5** (Barroso & Hölzle, 2007; Wang et al., 2020)
- **Sähköketju ja varmistus** → liittymäteho, jakelu, UPS/varavoima, varmistusperiaate (N / N+1 / 2N) ja häviöiden huomiointi → **Luku 5** (Geng, 2015; LVM, 2020)
- **Sähkön alkuperä ja päästöt** → todentamistapa (hankintamalli) ja päästökertoimien valinta raportointiin → **Luku 6** (Jin et al., 2016; LVM, 2020)
- **Jäähdytysratkaisu** → jäähdytysarkkitehtuuri ja jäähdytyksen sähköteho *P_cool(t)*; mitoituksen lähtötiedot (lämpökuorma ja olosuhteet) → **Luku 6** (Geng, 2015; Elavarasi et al., 2025)
- **Jäähdytyksen mittaus** → mittauspisteet ja aikasarjat (jäähdytyksen sähkö, lämpötilat, virtaus/ilmamäärä) IT-kuorman vertailuun → **Luku 7** (Geng, 2015; Elavarasi et al., 2025)
- **Hukkalämpö** → rajapinta, mitattava lämpöenergia (MWh), toimitusvastuut ja sopimuslähtötiedot → **Luku 6** (Geng, 2015; LVM, 2020)
- **Mittausrajat, mittarit ja raportointi** → mittausrajat, mittarit (PUE, REF, ERF, CER, CUE, WUE), mittauspisteet ja dokumentoidut laskentasäännöt → **Luku 7** (Uddin & Rahman, 2012; Jin et al., 2016; Geng, 2015)
- **Elinkaaren loppu** → käytöstäpoisto, tietojen hävittäminen ja materiaalivirrat (prosessit ja vastuut) → **Luku 4** (Geng, 2015)

**Huom.** Jäähdytysratkaisujen vaihtoehdot ja valintaperusteet (esim. ekonomaiseri, hybridi, direct-to-chip, immersio) käsitellään luvussa 6. Mittareiden mittauspisteet ja laskentasäännöt käsitellään luvussa 7.

---

## P1.9 Miksi sijainti käsitellään ennen ratkaisujen valintaa

Luku 2 käsittelee rakentamisen syitä ja sijaintipäätöksiä, koska sijainti määrittää useita tämän oppaan myöhempiä reunaehtoja. Sijaintipäätöksessä tarkastellaan sähköverkon kapasiteettia ja luotettavuutta, palvelutasoon liittyviä vaatimuksia (mm. saatavuus ja redundanssi), sähkön päästöintensiteettia ja uusiutuvan energian todentamista sekä jäähdytys- ja hukkalämpöratkaisujen edellyttämiä liityntöjä ja infrastruktuuria (Geng, 2015; Jin et al., 2016; LVM, 2020).

Lisäksi sijainti kytkeytyy viive- ja käyttäjävaatimuksiin: kuorman siirto alueiden välillä on mahdollista vain, jos palvelutaso sallii viiveen ja saatavuuden näkökulmasta (Wang et al., 2020; Jin et al., 2016).

---

## Lähteet (APA)

- Andrae, A. S. G., & Edler, T. (2015). *On global electricity usage of communication technology: Trends to 2030*. **Challenges, 6**(1), 117–157.
- Barroso, L. A., & Hölzle, U. (2007). *The case for energy-proportional computing*. **Computer, 40**(12), 33–37.
- Elavarasi, J., Thilagam, T., Amudha, G., Saratha, B., Ananthi, S. N., & Siva Subramanian, R. (2025). *Green data centers: Advancing sustainability in the digital era*. In *Proceedings of the International Conference on Trends in Material Science and Inventive Materials (ICTMIM-2025)* (pp. 1817–1823). IEEE.
- Garey, M. R., & Johnson, D. S. (1979). *Computers and intractability: A guide to the theory of NP-completeness*. W. H. Freeman.
- Geng, H. (Ed.). (2015). *Data center handbook*. John Wiley & Sons.
- Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). *Green data centers: A survey, perspectives, and future directions*. arXiv. (arXiv:1608.00687)
- LVM. (2020). *The ICT sector, climate and the environment – Interim report* (Publications of the Ministry of Transport and Communications 2020:14). Ministry of Transport and Communications, Finland.
- Masanet, E., Shehabi, A., Lei, N., Smith, S., & Koomey, J. (2020). *Recalibrating global data center energy-use estimates*. **Science, 367**(6481), 984–986.
- Sabree, R. M. S. (2025). *Achieving sustainability in computing by minimizing data center carbon footprints*. **Journal of Information Processing and Management**.
- Shehabi, A., Smith, S. J., Sartor, D., Brown, R., Herrlin, M., Koomey, J. G., Masanet, E., Horner, N., Azevedo, I. L., & Lintner, W. (2016). *United States data center energy usage report*. Lawrence Berkeley National Laboratory.
- Uddin, M., & Rahman, A. A. (2012). *Energy efficiency and low carbon enabler green IT framework for data centers considering green metrics*. **Renewable and Sustainable Energy Reviews, 16**(6), 4078–4094.
- Wang, J., Palanisamy, B., & Xu, J. (2020). *Sustainability-aware resource provisioning in data centers*. In *2020 IEEE 6th International Conference on Collaboration and Internet Computing (CIC)* (pp. 60–67). IEEE. https://doi.org/10.1109/CIC50333.2020.00018
- Whitney, J., & Delforge, P. (2014, August). *Data center efficiency assessment: Scaling up energy efficiency across the data center industry: Evaluating key drivers and barriers* (Issue Paper IP:14-08-a). Natural Resources Defense Council (NRDC) & Anthesis. https://www.nrdc.org/sites/default/files/data-center-efficiency-assessment-IP.pdf





