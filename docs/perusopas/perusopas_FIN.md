# Datakeskus vs. Vihreä datakeskus

## Mitä datakeskus on ja miksi niitä rakennetaan

- Perinteisen datakeskuksen energian- ja laitemitoitus  
## Datakeskus vs. Vihreä datakeskus

## Mitä datakeskus on ja miksi niitä rakennetaan

### Perinteisen datakeskuksen energian- ja laitemitoitus

Perinteisen datakeskuksen energian- ja laitemitoitus ankkuroituu usein historiadataan, josta muodostetaan (i) millaisia työpyyntöjä (job) keskukseen saapuu ja (ii) miten niiden määrä muuttuu ajassa (Wang et al., 2020).

Historiadatan työkuorma tyypitetään klusteroimalla (esim. muokattu k-means), jolloin syntyy joukko työtyyppejä (workload characterization) ja niiden tyyppijakauma (Wang et al., 2020). 

Kuorman ennusteessa (workload prediction) tulevien aikajaksojen työpyyntöjen määrää ennustetaan aikasarjamallilla (esim. ARIMA), jolloin saadaan arvio työpyyntöjen määrästä per aikaväli (Wang et al., 2020). 

Tällöin energian kulutuksen ja laitemitoituksen “perusta” on eksplisiittisesti: **ennustettu työpyyntöjen määrä + työtyyppien resurssiprofiilit** (Wang et al., 2020).

Palvelintarve johdetaan työpyyntöjen resurssivaatimuksista ja niiden suoritusaikavaatimuksista (deadlinet / SLA). Kun työtyypit on määritelty, jokaiselle työlle mallinnetaan vähintään CPU- ja muistivaatimus, ajoaika (execution duration) sekä deadline (Wang et al., 2020). 

Työtyypit sidotaan edelleen niihin palvelintyyppeihin, joilla työ voidaan ajaa (job–server mapping): palvelin on “kelpoinen”, jos sen CPU- ja muistiresurssit riittävät työn vaatimuksiin (Wang et al., 2020).

Laskentakapasiteettisuunnittelu voidaan muotoilla kokonaislukusuunnitteluongelmana (ILP), jossa päätetään, mitä palvelimia otetaan käyttöön (muuttuja *y*) ja mille palvelimelle kukin työ sijoitetaan (muuttuja *x*) (Wang et al., 2020). 

Tällaisessa mitoituslogiikassa jokainen työ sijoitetaan täsmälleen yhdelle palvelimelle, palvelimen CPU- ja muistirajat eivät ylity ja työ valmistuu ennen määräaikaa (Wang et al., 2020). 

Ongelma on laskennallisesti vaikea (NP-vaikea) ja kapasiteettimitotus voidaan kytkeä bin packing -tyyppisiin pakkausongelmiin; tästä seuraa, että käytännössä mitoitus tehdään usein heuristiikoilla täsmäratkaisun sijaan (Garey & Johnson, 1979).

Koska täsmäratkaisun löytäminen kapasiteetin mitoitukseen on vaikeaa, perinteiset datakeskukset mitoitetaan tavallisesti erilaisten heurististen menetelmien avulla. Tyypillinen lähestymistapa on “first-fit”-tyyppinen kapasiteettisuunnittelu, jossa työt sijoitetaan palvelimille niiden vapaan kapasiteetin ja määräaikojen perusteella, mutta valmistuksen tai käytön hiilijalanjälkeä ei eksplisiittisesti huomioida (Wang et al., 2020).

Energiamitoituksen kannalta keskeinen periaate on: kun palvelinmäärä ja kuorman sijoittelu (käyttöasteprofiili) on päätetty, voidaan laskea aktiivisten palvelinten energiankulutus ja siitä edelleen sähkönkulutus sekä päästöt. Wang et al. (2020) -mallinnus kytkee tämän nimenomaisesti palvelimien tehomalliin.

Tutkimuskirjallisuus ehdottaa energia- ja laitemitoituksen ankkuroimista IT-palvelutarpeeseen (sovellukset, alustat ja niiden kehitys) eikä pelkkään tehotiheysoletukseen (W/m²), jotta tilan, tehon ja jäähdytyksen tarve voidaan arvioida realistisesti (Geng, 2015). Tämä kapasiteettisuunnittelu on luonteeltaan “enterprise architecture” -tyyppistä: alustakohtainen historiakehitys ja kasvuennuste kytketään tulevaan kapasiteettiin, ja huomioidaan myös “refresh capacity” eli siirtymävaiheet, joissa vanha ja uusi järjestelmä voivat olla rinnakkain (Geng, 2015). Tässä mitoitusperiaattessa datakeskuksen sähkötehonmitoituksessa erotetaan pätöteho (W), loisteho (VAR), näennäisteho (VA) ja tehokerroin (PF), koska kuorman sähköinen luonne vaikuttaa siihen, miten paljon kapasiteettia verkosta ja varavoimasta todellisuudessa tarvitaan (Geng, 2015). Koska loisteho ja tehokerroin voivat rajoittaa kapasiteetin hyödynnettävyyttä, jos mitoitus tehdään vain yhden suureen perusteella ilman kokonaiskuvaa (Geng, 2015).

Yhteenvetona: perinteinen datakeskus voidaan mitoittaa joko sovellus- ja alustatasosta (Geng, 2015) tai tarkemmalla tasolla ennustetuista työpyynnöistä ja niiden resurssiprofiileista (Wang et al., 2020). 
Molemmissa tapauksissa lopputuloksena johdetaan IT-teho (kW), jonka varaan sähkö- ja jäähdytysinfrastruktuuri mitoitetaan (Geng, 2015; Wang et al., 2020).

---

### Perinteisten datakeskusten työpyyntöjen ja tilan käyttöaste

Perinteisten datakeskusten laskentaresurssien käyttöaste on tyypillisesti matala, mikä liittyy ylikapasiteetin mitoittamiseen (over-provisioning) ja staattisiin mitoitusperiaatteisiin (Jin et al., 2016; Whitney & Delforge, 2014). Laajassa toimialakatsauksessa on raportoitu keskimääräisen palvelinkäyttöasteen pysyneen noin **12–18 %** tasolla (2006–2012), kun taas **hyperskaalan pilvitoimijoilla** voidaan saavuttaa korkeampia käyttöasteita (raportoitu haarukka **40–70 %**), vaikkakaan ei välttämättä johdonmukaisesti kaikissa ympäristöissä (Whitney & Delforge, 2014).

Alhaista käyttöastetta selittää ensinnäkin systemaattinen ylikapasiteetin mitoittaminen: kapasiteetti mitoitetaan harvinaisten huipputilanteiden, pitkän aikavälin kasvuennusteiden ja redundanssivaatimusten (esim. N+1 tai 2N) perusteella (Whitney & Delforge, 2014). Tällöin sähkö- ja jäähdytysinfrastruktuuri sekä IT-laitteet rakennetaan kestämään huiput, vaikka kuorma olisi suurimman osan ajasta selvästi alle mitoitusarvon.

Toiseksi kapasiteettisuunnittelu on usein staattista. Resursseja lisätään karkeina askelina (esim. kokonaiset räkit, UPS-yksiköt), jolloin vuorokausi- ja viikkorytmit, kausivaihtelut ja palveluiden elinkaarimuutokset eivät heijastu mitoitukseen, mikä vahvistaa ylikapasiteettia (Jin et al., 2016; Whitney & Delforge, 2014). 

Kolmanneksi sovelluksia ja asiakkaita eristetään infrastruktuurissa organisatorisista ja turvallisuussyistä; ilman pitkälle vietyä virtualisointia ja konsolidointia tämä voi johtaa siihen, että kokonaisia palvelimia varataan pienikuormaisille järjestelmille (Whitney & Delforge, 2014).

Neljänneksi laitteiden energiankulutus ei useinkaan skaalaudu lineaarisesti kuorman mukana: palvelimet kuluttavat merkittävän osan huipputehostaan myös pienellä kuormalla tai lähes tyhjäkäynnillä. 

Katsauksissa on kuvattu, että matalalla käyttöasteella (esim. ~10 %) palvelimet voivat silti käyttää noin **30–60 %** maksimitehostaan, ja klassisessa energiaproportionaalisuuden analyysissä todetaan, että jopa energiatehokas palvelin kuluttaa tyhjäkäynnillä noin **puolet** huipputehostaan (Barroso & Hölzle, 2007; Whitney & Delforge, 2014). Tästä seuraa, että ylikapasiteetti näkyy suoraan ylimääräisenä energiankulutuksena ja siten myös kasvaneina päästöinä (Jin et al., 2016; Whitney & Delforge, 2014).

---

## Lähteet (APA)

Barroso, L. A., & Hölzle, U. (2007). The case for energy-proportional computing. *Computer, 40*(12), 33–37.

Garey, M. R., & Johnson, D. S. (1979). *Computers and intractability: A guide to the theory of NP-completeness*. W. H. Freeman.

Geng, H. (Ed.). (2015). *Data center handbook*. John Wiley & Sons.

Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). Green data centers: A survey, perspectives, and future directions. *arXiv*. (arXiv:1608.00687)

Wang, J., Palanisamy, B., & Xu, J. (2020). Sustainability-aware resource provisioning in data centers. In *2020 IEEE 6th International Conference on Collaboration and Internet Computing (CIC)* (pp. 60–67). IEEE. `https://doi.org/10.1109/CIC50333.2020.00018`

Whitney, J., & Delforge, P. (2014, August). *Data center efficiency assessment: Scaling up energy efficiency across the data center industry: Evaluating key drivers and barriers* (Issue Paper IP:14-08-a). Natural Resources Defense Council (NRDC) & Anthesis. ([nrdc.org][1])

[1]: https://www.nrdc.org/sites/default/files/data-center-efficiency-assessment-IP.pdf "NRDC: Data Center Efficiency Assessment - Scaling Up Energy Efficiency Across the Data Center Industry - Evaluating Key Drivers and Barriers (PDF)"

---

### Kansainvälinen kasvu: sähkönkulutus, CO₂-päästöt ja kustannukset

Tietoteknisesti datakeskus voidaan määritellä fyysiseksi infrastruktuuriksi, jossa palvelin-, tallennus- ja verkkolaitteet sekä niitä tukeva sähkö-, jäähdytys- ja valvontajärjestelmä on keskitetty yhteen tilaan siten, että laskentateho, tietovarastot ja verkkopalvelut voidaan tuottaa luotettavasti ja skaalautuvasti (Jin, Zhang, Vasilakos, & Liu, 2016).  
Datakeskuksia rakennetaan ennen kaikkea digitalisaation, pilvipalvelujen ja verkottuneiden sovellusten globaalin kasvun palvelemiseksi: hajallaan olevia, tehottomia konesaleja korvataan keskistetyillä ympäristöillä, joissa kapasiteetti, automaatio ja operointi voidaan optimoida teollisessa mittakaavassa (Jin et al., 2016; Shehabi et al., 2016).

Energiatalouden näkökulmasta datakeskuksista on tullut merkittävä sähkönkuluttaja. Kansainvälinen analyysi osoittaa, että datakeskusten osuus maailman loppusähkönkulutuksesta oli 2010-luvun lopussa suuruusluokkaa 1 %, vaikka laskentakapasiteetti ja käsitellyn datan määrä kasvoivat moninkertaisiksi samana ajanjaksona (Masanet, Shehabi, Lei, Smith, & Koomey, 2020). Yhdysvaltoja koskeva yksityiskohtainen tarkastelu tukee samaa havaintoa: datakeskusten sähkönkulutuksen voimakas kasvu hidastui 2010-luvulla selvästi, kun virtualisointi, palvelinkonsolidointi ja energiatehokkaammat laitteet yleistyivät (Shehabi et al., 2016).

Näiden tulosten perusteella uusia datakeskuksia ei rakenneta ainoastaan lisäämään raakaa kuormaa, vaan myös kokoamaan hajautuneita, vajaakäyttöisiä laitteistoja energiatehokkaampiin, korkeaa käyttöastetta tukeviin ympäristöihin (Jin et al., 2016; Masanet et al., 2020).

Useat pitkän aikavälin skenaariot kuitenkin osoittavat, että ilman lisätoimia ICT-sektorin – ja erityisesti datakeskusten – sähkönkäyttö voisi kasvaa useisiin prosentteihin maailman kokonaiskulutuksesta, jos liikennemäärät, datan tallennus ja palveluiden kysyntä jatkavat nykyistä kasvuvauhtiaan (Andrae & Edler, 2015). Viimeaikainen tutkimus on korostanut erityisesti generatiivisen tekoälyn, suurten kielimallien ja muun suuritehoisen laskennan aiheuttamaa uutta kuormitusta: suurten GPU-klustereiden energiatiheys on huomattavasti perinteisiä konesaleja suurempi, ja niiden nopea käyttöönotto uhkaa murtaa 2010-luvulle tyypillisen “tehokkuuden ansiosta tasaisen” kulutuskehityksen (Sabree, 2025; Masanet et al., 2020).  

Tämä kehityskulku tekee uudesta datakeskushankkeesta paitsi IT-investoinnin myös energia- ja ilmastopoliittisen kysymyksen.

Datakeskuksen hiilijalanjälki määräytyy karkeasti kahden tekijän tulona: käytetty sähköenergia (kWh) ja sähköjärjestelmän päästökerroin (kgCO₂/kWh) (Jin et al., 2016; Sabree, 2025).  
Kansainväliset analyysit osoittavat, että alueilla, joilla sähkö tuotetaan pääosin fossiilisilla polttoaineilla, datakeskukset muodostavat nopeasti merkittävän osuuden paikallisista energiasektorin päästöistä (Sabree, 2025). Vastaavasti maissa, joissa sähköntuotanto on valmiiksi vähäpäästöistä, datakeskukset voivat toimia tehokkaana tapana tuottaa globaaleja digitaalisia palveluja mahdollisimman pienellä hiilijalanjäljellä: kun kuorma keskitetään moderniin, hyvin mitoitettuun keskukseen, sama palvelukapasiteetti voidaan toteuttaa murto-osalla siitä energiasta ja CO₂-päästöistä, joita hajautetut ja teknisesti vanhentuneet konesalit kuluttaisivat (Masanet et al., 2020; LVM, 2020).

Taloudellisesti sähkö- ja jäähdytyskulut muodostavat huomattavan osan datakeskuksen elinkaarikustannuksista.  
Empiiriset tutkimukset osoittavat, että energiatehokkuuteen panostaminen – esimerkiksi vapaajäähdytyksen hyödyntäminen, korkeaa hyötysuhdetta tukevat UPS-ratkaisut ja kuorman konsolidointi harvemmille, mutta tehokkaammin käytetyille palvelimille – pienentää kokonaiskustannuksia usein jo muutaman vuoden aikajänteellä (Jin et al., 2016; Shehabi et al., 2016). Samanaikaisesti ilmastotavoitteet, energiatehokkuusdirektiivit ja yritysasiakkaiden vastuullisuusvaatimukset ohjaavat investointeja kohti datakeskuksia, jotka pystyvät osoittamaan matalan PUE-arvon, korkean uusiutuvan energian osuuden ja läpinäkyvät päästöraportit (Sabree, 2025; LVM, 2020).  

Näin energiatehokkuus ja vähäpäästöinen sähkö toimivat sekä kustannusten leikkaajina että kilpailuetuna datakeskusmarkkinoilla.

Suomen näkökulmasta kansainvälinen tutkimuskirjallisuus tukee käsitystä, että vihreä datakeskus on erityisen järkevä sijoittaa alueille, joilla sähköntuotanto on pääosin hiilineutraalia, ilmasto mahdollistaa laajan vapaajäähdytyksen käytön ja sähköverkko on luotettava (Jin et al., 2016; LVM, 2020). Tällöin datakeskusinvestointi palvelee samanaikaisesti globaalia digitaalista kysyntää, kansallista vihreän siirtymän strategiaa sekä datakeskustoimijan omia taloudellisia tavoitteita.

### Lähteet (APA)

Andrae, A. S. G., & Edler, T. (2015). On global electricity usage of communication technology: Trends to 2030. *Challenges, 6*(1), 117–157.  
Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). Green data centers: A survey, perspectives, and future directions. *arXiv preprint* arXiv:1608.00687.  
LVM. (2020). *The ICT sector, climate and the environment – Interim report* (LVM 2020:14). Ministry of Transport and Communications, Finland.  
Masanet, E., Shehabi, A., Lei, N., Smith, S., & Koomey, J. (2020). Recalibrating global data center energy-use estimates. *Science, 367*(6481), 984–986.  
Sabree, R. M. S. (2025). Achieving sustainability in computing by minimizing data center carbon footprints. *Journal of Information Processing and Management*.  
Shehabi, A., Smith, S. J., Sartor, D., Brown, R., Herrlin, M., Koomey, J. G., Masanet, E., Horner, N., Azevedo, I. L., & Lintner, W. (2016). *United States data center energy usage report*. Lawrence Berkeley National Laboratory.  


---



## Vihreä datakeskus: määritelmä ja tavoitteet

Vihreä datakeskus määritellään datakeskukseksi, jossa mekaaniset, valaistus-, sähkö- ja tietotekniset järjestelmät on suunniteltu ja toteutettu siten, että energiankäyttö on mahdollisimman tehokasta ja ympäristövaikutukset, erityisesti kasvihuonekaasupäästöt, mahdollisimman vähäisiä (Uddin & Rahman, 2012). Uddin ja Rahman korostavat, että vihreä datakeskus on edelleen normaalin datakeskuksen tavoin tiedon tallennuksen, käsittelyn ja jakelun keskus, mutta sen infrastruktuuri – ohjelmistot, IT-laitteet ja rakennus-/talotekniikka – on optimoitu energiatehokkuuden ja kestävyyden näkökulmasta eikä ainoastaan kapasiteetin ja käytettävyyden perusteella (Uddin & Rahman, 2012).

Elavarasi et al. (2025) määrittelee vihreän datakeskuksen nykyaikaisena laskentaympäristönä, jossa tavoitteena on käyttää kokonaisuudessaan vähemmän energiaa, lisätä uusiutuvan energian osuutta ja parantaa energian käytön kokonaishyötysuhdetta (Elavarasi et al., 2025). Heidän esittämänsä vihreän datakeskuksen keskeiset komponentit ovat energiatehokas infrastruktuuri (korkean hyötysuhteen muuntajat, modulaariset UPS-ratkaisut ja suorituskykyiset virtalähteet), kehittyneet jäähdytysjärjestelmät (nestekierto, ilma- ja vesiekonomaiserit, immersiojäähdytys*) sekä uusiutuvan energian ja energiavarastojen integraatio, joita ohjaavat päästö- ja tehokkuusmittarit, kuten PUE ja CUE (Elavarasi et al., 2025).

*Data Center Handbook* -teoksessa vihreän datakeskuksen ideaalitilaa kuvataan yhdistelmänä erittäin energiatehokasta infrastruktuuria (PUE lähellä 1,0), korkeaa IT-laitteiden käyttöastetta ja matalaa hiili-intensiteettiä, jota seurataan esimerkiksi CUE-mittarin avulla (Geng, 2015).

Kirja korostaa, että uusissa yritysdatasaleissa vihreyttä tavoitellaan erityisesti integroimalla uusiutuvia energialähteitä (tuuli, aurinko, vesi, geoterminen energia, polttokennot) sekä ottamalla järjestelmällisesti käyttöön energiatehokkuuden mittaristo ja parannusohjelmat (Geng, 2015).

Tutkimuskirjallisuuteen pohjautuen perinteisen datakeskuksen ja vihreän datakeskuksen keskeinen ero voidaan tiivistää tavoitteisiin ja suunnittelufilosofiaan. Perinteisessä datakeskuksessa kapasiteetti ja käytettävyys on usein varmistettu ylikapasitoinnilla, mikä johtaa alhaiseen käyttöasteeseen ja sitä kautta energiatehokkuuden heikkenemiseen sekä tarpeettoman suuriksi kasvaviin sähkö- ja jäähdytysinvestointeihin (Jin et al., 2016; Uddin & Rahman, 2012). Vihreä datakeskus sen sijaan yhdistää suunnittelussa ja operoinnissa kolme rinnakkaista tavoitetta: (i) luotettava ja riittävä laskentakapasiteetti, (ii) minimointi koko elinkaaren aikaiselle energiankulutukselle ja hiilijalanjäljelle sekä (iii) kustannustehokkuus, jota tukevat energiatehokkuuden mittarit ja jatkuva optimointi (Jin et al., 2016; Elavarasi et al., 2025).

Käytännössä tämä ero näkyy muun muassa siinä, että vihreässä datakeskuksessa palvelinresursseja hallitaan virtualisoinnin ja konsolidoinnin avulla, sähkönjakelu ja UPS-ratkaisut on valittu pienentämään muuntohäviöitä ja jäähdytysratkaisut hyödyntävät mahdollisuuksien mukaan ulkoilmaa, nestekiertoa tai immersiojäähdytystä* perinteisen kompressorijäähdytyksen sijaan (Uddin & Rahman, 2012; Elavarasi et al., 2025). Lisäksi vihreissä datakeskuksissa energiantuotannon hiili-intensiteettiä pienennetään kytkemällä keskus vähäpäästöiseen verkkoon tai omaan uusiutuvaan tuotantoon, usein yhteistyössä energiavarastojen ja mikroverkkojen kanssa (Elavarasi et al., 2025).

Yhteenvetona voidaan todeta, että vihreä datakeskus ei ole erillinen datakeskustyyppi, vaan tieteelliseen tutkimukseen perustuva malli, jossa perinteisen datakeskuksen toiminnalliset vaatimukset säilyvät, mutta suunnittelua ja operointia ohjaavat lisäksi selkeästi määritellyt energia- ja ympäristötavoitteet, joita mitataan ja optimoidaan systemaattisesti (Jin et al., 2016; Uddin & Rahman, 2012; Elavarasi et al., 2025; Geng, 2015).

* Immersiojäähdytys (engl. immersion cooling) tarkoittaa, että lämpöä tuottavat elektroniikkakomponentit – tyypillisesti palvelimien emolevyt ja piirit – jäähdytetään upottamalla ne suoraan sähköä johtamattomaan nesteeseen. Neste vie lämmön pois paljon tehokkaammin kuin ilma, ja lämpö voidaan sitten siirtää lämmönvaihtimella pois (esim. vesi- tai glykolikiertoon).
 
### Lähteet (APA)

- Elavarasi, J., Thilagam, T., Amudha, G., Saratha, B., Ananthi, S. N., & Siva Subramanian, R. (2025). Green data centers: Advancing sustainability in the digital era. In *Proceedings of the International Conference on Trends in Material Science and Inventive Materials (ICTMIM-2025)* (pp. 1817–1823). IEEE.
- Geng, H. (Ed.). (2015). *Data Center Handbook*. Wiley.
- Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). Green data centers: A survey, perspectives, and future directions. *arXiv preprint* arXiv:1608.00687.
- Uddin, M., & Rahman, A. A. (2012). Energy efficiency and low carbon enabler green IT framework for data centers. *Renewable and Sustainable Energy Reviews, 16*, 4078–4094.

---

## Käyttöasteen nostaminen ja energian kulutuksen optimointi  

Vihreän datakeskuksen keskeinen tavoite on kääntää perinteisten datakeskusten rakenteellisesti alhaisen käyttöasteen ja huonon energian käytön tehokkuuden suhde: nostaa IT-kapasiteetin käyttöastetta ja samalla pienentää kokonaisenergiankulutusta palvelutasovaatimuksista tinkimättä. Tämä toteutetaan kolmella pääkeinolla: (1) dynaamisella resurssien provisioinnilla ja kuormien konsolidoinnilla, jossa virtuaalipalvelimet pakataan mahdollisimman harvoille fyysisille palvelimille; (2) energiatietoisten ajoitusalgoritmien avulla, joissa työkuormia siirretään energiatehokkaimpiin laite- ja aikajaksoihin; sekä (3) säätämällä prosessorien ja muiden komponenttien tehoa käyttöasteen mukaan. Tällöin energiankulutus pyritään tekemään mahdollisimman “proportionaaliseksi” tuotettuun laskentatyöhön, mikä vähentää sekä operatiivisia kustannuksia että hiilijalanjälkeä (Wang, Palanisamy & Xu, 2020; Jin et al., 2016).

Suomen oloihin sovellettuna käyttöasteen nosto ja energian optimointi korostuvat erityisesti siksi, että sähkö on jo lähtökohtaisesti vähäpäästöistä, mutta kallista. Kansallinen tarkastelu osoittaa, että datakeskusten sähkökulut ovat tyypillisesti 40–70 % kokonaiskäyttökustannuksista, ja siksi energiahäviöiden minimointi sekä IT-laitteissa että jäähdytyksessä on taloudellisesti rationaalista.

Vihreän datakeskuksen suunnittelu Suomessa voidaan siten nähdä investointina, joka yhdistää korkeamman käyttöasteen, pienemmät sähkö- ja jäähdytyskustannukset sekä EU:n ilmasto- ja energiatavoitteiden mukaisen päästövähennyksen (Ministry of Transport and Communications Finland, 2020).

### Lähteet (APA)

- Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). Green data centers: A survey, perspectives, and future directions. *arXiv preprint* arXiv:1608.00687.
- Ministry of Transport and Communications Finland. (2020). *The ICT sector, climate and the environment* (Publications of the Ministry of Transport and Communications 2020:14).
- Wang, J., Palanisamy, B., & Xu, J. (2020). Sustainability-aware resource provisioning in data centers. In *Proceedings of the 2020 IEEE International Conference on Services Computing* (pp. 65–73). IEEE.



 Ilmasto- ja sääntelyvaatimusten vaikutus  




# Suomi datakeskuksen sijoituspaikkana
Suomi lähtökohtana”
Sähkömarkkina ja uusiutuvan sähkön hankinta (PPA / alkuperätakuut)
Kylmä ilmasto → free cooling -potentiaali
Kaukolämpöverkot ja hukkalämmön hyödyntäminen (kannattaako liittää)
Sijainti: kuituyhteydet, sähköliittymä, tontti, luvitus, melu, vesiasiat
A. Fakta (miksi tärkeä) jäähdytys voi olla suurin IT:n ulkopuolinen kuluttaja
B. Tavoite (mitä mitataan) laske jäähdytyksen energia per IT-kWh
C. Suunnitteluvaihtoehdot (2–4 vaihtoehtoa) 
D. Valintakriteerit Suomessa (milloin mikäkin) Suomi-kriteerit: ulkolämpötilajakauma, vesirajoitteet, huolto-osaaminen
E. Riskit ja varmistukset kondenssi, vedenkulutus, huolto, yhteensopivuus
F. Tarkistuslista mittarit, anturit, hälytykset, redundanssi





## Ilmasto, vapaajäähdytys ja ympäristön olosuhteet
- Viileä ilmasto ja mahdollisuus free cooling -ratkaisuihin  
- Matalien ulkolämpötilojen hyödyntäminen jäähdytyksessä  



## Uusiutuva energia ja puhdas sähkö
- Tuuli-, aurinko- ja vesivoiman saatavuus ja verkon päästökertoimet  
- Sähköverkon kapasiteetti ja varmuus  


## Infrastruktuuri ja viive
- Kuitu- ja energiainfrastruktuuri  
- Käyttäjäviive ja palveluiden saavutettavuus  


## Esimerkit suomalaisista sijaintistrategioista
- Kaukolämpöverkkoon kytketyt datakeskukset  
- Pilvi- ja HPC-keskusten sijoittumisratkaisut  


# Perusopas vihreän datakeskuksen rakentamiseksi Suomessa
## 1. Rakentamisen syyt ja sijaintipäätökset
Datakeskusten määrä ja koko kasvavat pilvipalveluiden ja digitaalisten palveluketjujen vuoksi. Samalla datakeskusten energiankulutus ja siitä seuraavat kustannus- ja päästövaikutukset ovat nousseet keskeiseksi suunnittelukriteeriksi. Jin ym. (2016) kokoavat yhteen tutkimusnäyttöä siitä, että merkittävä osa nykyisestä energiankulutuksesta ei johdu vain laskentakuorman kasvusta, vaan myös rakenteellisesta tehottomuudesta: resursseja ylivarmistetaan, kapasiteettia pidetään varalla ja käyttöaste jää matalaksi, mikä kasvattaa myös jäähdytyksen ja sähkönjakelun “tyhjäkäyntiä”. arXiv

Artikkelin mukaan Yhdysvaltain datakeskusten sähkönkulutus oli 2013 noin 91 mrd kWh ja ennuste 2020 noin 140 mrd kWh, ja globaalisti datakeskusten sähkönkulutuksen osuuden on arvioitu kasvavan merkittävästi. 
arXiv Lisäksi tutkimusviitteet korostavat käyttöasteongelmaa: tyypillisiä palvelinkäyttöasteita on raportoitu noin 6–12 % tasolla, kun taas parhaat toimijat ovat pystyneet nostamaan käyttöastetta selvästi korkeammaksi (esim. 20–40 %). arXiv Tämä tarkoittaa sähkö- ja jäähdytysinfran näkökulmasta, että “vihreän datakeskuksen” rakentamisen keskeinen perustelu on usein saman palvelukyvyn tuottaminen pienemmällä energialla, joko parantamalla käyttöastetta (konsolidointi, virtualisointi, kuormanohjaus) tai pienentämällä infrastruktuurin häviöitä ja jäähdytyksen tarvetta – mielellään molempia.arXiv 
Jin ym. (2016) jäsentävät vihreät ratkaisut kahteen pääluokkaan: (1) suunnittelu- ja rakennusvaiheen “vihreät laitteet ja infrastruktuuri” sekä (2) operoinnin aikaiset tehokkuus- ja optimointimenetelmät (energiatehokkuus, resurssien hallinta, lämpötilan ja jäähdytyksen ohjaus, mittarointi). arXiv Oppaan näkökulmasta tämä on tärkeä periaate: sijainti ja sähköinen infrastruktuuri luovat tehokkuuskaton, mutta operointi ratkaisee, päästäkö kattoon.

Sijaintipäätös sähköisen infrastruktuurin ja energian näkökulmasta (Suomi)
Sijaintipäätös kannattaa tehdä sähkö- ja energiavirtojen ehdoilla jo varhaisessa vaiheessa, koska teho- ja liittymärajoitteet, redundanssivaatimukset sekä energian alkuperä lukitsevat pitkälti sekä investoinnin että elinkaaren päästöprofiilin. Tutkimusnäytön perusteella sijaintiin liittyy erityisesti neljä käytännön kannalta ratkaisevaa tekijää:

1.Sähköverkon kapasiteetti ja luotettavuus
Vahva verkko ja realistinen liittymäpolku ovat edellytys kilpailukykyiselle investoinnille: mitä heikompi verkko, sitä enemmän tarvitaan kalliita paikallisia ratkaisuja (varasyötöt, jakelu, mahdolliset tehorajoitteet ja pitkät aikataulut). arXiv Oppaaseen kirjattava käytäntö: varmista varhain sähköverkkoyhtiöltä vapaa kapasiteetti, aikataulu ja kustannusrakenne (liityntä/tehomaksut) sekä mahdollisuus kahteen syöttöön (2N tai N+1 palvelutasotarpeen mukaan).

2. Sähkön päästöintensiteetti ja uusiutuvan energian saatavuus
Vihreän datakeskuksen “energia- ja ympäristötavoitteet” eivät toteudu ilman matalapäästöistä sähköä. Jin ym. nostavat uusiutuvan energian saatavuuden ja päästöohjautuvan optimoinnin vihreiden ratkaisujen ytimeen. 
arXiv Oppaaseen kirjattava käytäntö: arvioi vaihtoehdot (PPA, alkuperätakuut, oma tuotanto) ja dokumentoi, miten sähkön alkuperä ja päästökerroin raportoidaan.

3. Ilmasto ja vapaajäähdytys (free cooling)
Pitkä viileä kausi pienentää jäähdytyksen energiankulutusta ja voi yksinkertaistaa järjestelmiä. Tämä on suora Suomen kilpailuetu: useissa sijainneissa voidaan hyödyntää free cooling -ratkaisuja suuren osan vuodesta, mikä laskee jäähdytyksen osuutta kokonaisenergiasta. arXiv Oppaaseen kirjattava käytäntö: laske suunnittelussa free cooling -tuntipotentiaali (lämpötila + kosteus) ja määritä jäähdytysratkaisu sen mukaan (air-/water-side economizer, hybridit).

4. Hukkalämmön hyödyntäminen
Hukkalämmön talteenotto ja hyödyntäminen on vihreän datakeskuksen keskeinen kilpailutekijä: se muuttaa “hukasta” hyödykkeen ja parantaa kokonaisjärjestelmän ympäristötehokkuutta. 
arXiv Oppaaseen kirjattava käytäntö: tee sijaintivaiheessa “lämmön vastaanottajakartoitus” (kaukolämpö / teollisuus / kiinteistöt), ja tarkista lämpötila- ja tehovaatimukset sekä etäisyys ja liittymiskustannukset.

Lisäksi sijaintipäätöksessä on aina tasapainotettava viive ja käyttäjävaatimukset: kuormaa voidaan ohjata edullisemman ja puhtaamman energian alueille vain, jos palvelun latenssi- ja saatavuusrajat sallivat sen. 
arXiv 

Lähde
Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). Green Data Centers: A Survey, Perspectives, and Future Directions (arXiv:1608.00687). arXiv.


## 2. Vihreän datakeskuksen peruselementit ja periaatteet
- ICT-laitteiden energiatehokkuus: DVFS, power-down-tilat  
- Resurssienhallinta: virtualisointi, kuormien ja liikenteen optimointi, power capping  
- Lämpötilanhallinta: free cooling, kuuma/kylmä-käytävä, lämpötilarajat  
- Vihreät mittarit ja valvonta: PUE, CUE, komponenttien hyötysuhdemittaus  

Tavoite: kuvata rakennuspalikat ja vaihtoehdot niin, että lukija voi valita järkevästi.
Rakenna moduuleiksi:
Sähkö: syötöt, UPS, generaattorit, jakelu, häviöiden minimointi.
Jäähdytys: ilma vs neste, free cooling, adiabatic, immersion/nestejäähdytys (milloin kannattaa).
IT: palvelintiheys, virtualisointi, kuormanhallinta.
Rakennus: ilmavirrat, tiiveys, modulaarisuus, huollettavuus.
Valintataulukko: “sopii / ei sovi” eri tehotasoille ja tavoitteille.


## 3. Elinkaaren vaiheet
- Tarveselvitys ja sijainti: kuormaprofiilit, kriittisyysluokat, sähkö- ja lämpöresurssit  
- Suunnittelu ja mitoitus: laitevalinnat, arkkitehtuuri, sähkö- ja jäähdytysketju  
- Rakentaminen ja käyttöönotto: testaus, PUE-mittaukset, ohjausstrategiat  
- Operointi ja optimointi: VM-konsolidointi, lämpökuorman hallinta, verkko-ohjaus  
- Modernisointi ja purku: laitepäivitykset, UPS- ja akkukemian vaihdot, kierrätys  

Elinkaari (LCA-ajattelu käytännössä)
Tavoite: estää “vihreä vain käyttövaiheessa” -ansa.
Sisällytä:
Hankinta → käyttö → laajennus → käytöstäpoisto.
Materiaalit, huolto, varaosat, uudelleenkäyttö, kierrätys.
Kapasiteetin suunnittelu: modulaarinen kasvu vs ylibuukkaus.
Minimi vs hyvä vs huippu -tasot (helppo arvioida).


## 4. Toiminta vaiheittain
- Hetkellinen kuorma ja kapasiteetin valinta  
- Virtuaalikoneiden sijoittelu ja palvelinparkit  
- Verkon energiatehokas ohjaus: reititys, linkkien sammuttaminen  
- Sähkönjakelun tehorajat ja varavoima: power-capping, akkujen/UPSien käyttö  
- Jäähdytys ja lämpötilan hallinta: CRAC/vesi, TES-varastot, tuloilman lämpötilan optimointi  
- Energiavirtamittaus ja palaute: PUE, CUE, lämpötilat, ilmavirrat  

Toiminta (operointi ja arjen ohjaus)
Tavoite: vihreys syntyy eniten vasta käytössä (ohjaus, optimointi, prosessit).
Sisällytä:
Käyttöönotto, muutoksenhallinta, incident/maintenance.
Optimointi: lämpötilasetpointit, ilmavirran ohjaus, kuorman siirto, huoltoikkunat.
Palvelutasot vs energiatavoitteet: miten sovitetaan yhteen.
Toimintamallit: “päivittäinen”, “viikoittainen”, “kvartaaleittain” tehtävät.


## 5. Energian kulutus ja uudelleenkäyttö
- Kulutuslähteet: palvelimet, verkko, jäähdytys, sähkönjakelu  
- Energian säästö: DVFS, sleep-tilat, free cooling, kuuman ja kylmän ilman erottelu  
- Uudelleenkäyttö: hukkalämmön hyödyntäminen (kaukolämpö, prosessilämpö)  
- Uusiutuvan energian käyttö ja varastointi: PV, tuuli, energian varastointi  

Energia ja hukkalämpö (vihreyden ydin)
Tavoite: tehdä energiavirrat näkyviksi ja hyödyttää lämpö.
Sisällytä:
Sähkön hankinta (uusiutuva, sopimukset periaatetasolla), kulutusprofiili.
Hukkalämmön talteenotto: lämpötilatasot, lämmönvaihdin, vastaanottaja, sopimuslogiikka.
“Kannattaako?”-osio: yksinkertainen päätöspuu (lämpömäärä + vastaanottaja + etäisyys).
Yksi esimerkkilasku (karkealla tasolla), jotta lukija ymmärtää suuruusluokat.


## 6. Energiatehokkuuden mittaaminen
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



