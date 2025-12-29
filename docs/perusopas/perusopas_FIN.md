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
Suomi lähtökohtana

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
Datakeskusten määrä ja koko kasvavat pilvipalveluiden ja digitaalisten palveluketjujen vuoksi. Samalla datakeskusten energiankulutus ja siitä seuraavat kustannus- ja päästövaikutukset ovat nousseet keskeiseksi suunnittelukriteeriksi. Merkittävä osa nykyisestä energiankulutuksesta ei johdu vain laskentakuorman kasvusta, vaan myös rakenteellisesta tehottomuudesta: resursseja ylivarmistetaan, kapasiteettia pidetään varalla ja käyttöaste jää matalaksi, mikä kasvattaa myös jäähdytyksen ja sähkönjakelun “tyhjäkäyntiä” [1].

Yhdysvaltain datakeskusten sähkönkulutus oli 2013 noin 91 mrd kWh ja ennuste 2020 noin 140 mrd kWh, ja globaalisti datakeskusten sähkönkulutuksen osuuden on arvioitu kasvavan merkittävästi [1]. Lisäksi tutkimusviitteet korostavat käyttöasteongelmaa: tyypillisiä palvelinkäyttöasteita on raportoitu noin 6–12 % tasolla, kun taas parhaat toimijat ovat pystyneet nostamaan käyttöastetta selvästi korkeammaksi (esim. 20–40 %) [1]. Tämä tarkoittaa sähkö- ja jäähdytysinfran näkökulmasta, että “vihreän datakeskuksen” rakentamisen keskeinen perustelu on usein saman palvelukyvyn tuottaminen pienemmällä energialla, joko parantamalla käyttöastetta (konsolidointi, virtualisointi, kuormanohjaus) tai pienentämällä infrastruktuurin häviöitä ja jäähdytyksen tarvetta – mielellään molempia [1]. 
Jin ym. (2016) jäsentävät vihreät ratkaisut kahteen pääluokkaan: (1) suunnittelu- ja rakennusvaiheen “vihreät laitteet ja infrastruktuuri” sekä (2) operoinnin aikaiset tehokkuus- ja optimointimenetelmät (energiatehokkuus, resurssien hallinta, lämpötilan ja jäähdytyksen ohjaus, mittarointi). arXiv Oppaan näkökulmasta tämä on tärkeä periaate: sijainti ja sähköinen infrastruktuuri luovat tehokkuuskaton, mutta operointi ratkaisee, päästäkö kattoon.

Sijaintipäätös sähköisen infrastruktuurin ja energian näkökulmasta (Suomi)
Sijaintipäätös kannattaa tehdä sähkö- ja energiavirtojen ehdoilla jo varhaisessa vaiheessa, koska teho- ja liittymärajoitteet, redundanssivaatimukset sekä energian alkuperä lukitsevat pitkälti sekä investoinnin että elinkaaren päästöprofiilin. Tutkimusnäytön perusteella sijaintiin liittyy erityisesti neljä käytännön kannalta ratkaisevaa tekijää:

1.Sähköverkon kapasiteetti ja luotettavuus
Vahva verkko ja realistinen liittymäpolku ovat edellytys kilpailukykyiselle investoinnille: mitä heikompi verkko, sitä enemmän tarvitaan kalliita paikallisia ratkaisuja (varasyötöt, jakelu, mahdolliset tehorajoitteet ja pitkät aikataulut). arXiv Oppaaseen kirjattava käytäntö: varmista varhain sähköverkkoyhtiöltä vapaa kapasiteetti, aikataulu ja kustannusrakenne (liityntä/tehomaksut) sekä mahdollisuus kahteen syöttöön (2N tai N+1 palvelutasotarpeen mukaan).

2. Sähkön päästöintensiteetti ja uusiutuvan energian saatavuus
Vihreän datakeskuksen “energia- ja ympäristötavoitteet” eivät toteudu ilman matalapäästöistä sähköä. Jin ym. nostavat uusiutuvan energian saatavuuden ja päästöohjautuvan optimoinnin vihreiden ratkaisujen ytimeen  
[1]. Oppaaseen kirjattava käytäntö: arvioi vaihtoehdot (PPA, alkuperätakuut, oma tuotanto) ja dokumentoi, miten sähkön alkuperä ja päästökerroin raportoidaan.

3. Ilmasto ja vapaajäähdytys (free cooling)
Pitkä viileä kausi pienentää jäähdytyksen energiankulutusta ja voi yksinkertaistaa järjestelmiä. Tämä on suora Suomen kilpailuetu: useissa sijainneissa voidaan hyödyntää free cooling -ratkaisuja suuren osan vuodesta, mikä laskee jäähdytyksen osuutta kokonaisenergiasta. arXiv Oppaaseen kirjattava käytäntö: laske suunnittelussa free cooling -tuntipotentiaali (lämpötila + kosteus) ja määritä jäähdytysratkaisu sen mukaan (air-/water-side economizer, hybridit).

4. Hukkalämmön hyödyntäminen
Hukkalämmön talteenotto ja hyödyntäminen on vihreän datakeskuksen keskeinen kilpailutekijä: se muuttaa “hukasta” hyödykkeen ja parantaa kokonaisjärjestelmän ympäristötehokkuutta. 
arXiv Oppaaseen kirjattava käytäntö: tee sijaintivaiheessa “lämmön vastaanottajakartoitus” (kaukolämpö / teollisuus / kiinteistöt), ja tarkista lämpötila- ja tehovaatimukset sekä etäisyys ja liittymiskustannukset [1].

Lisäksi sijaintipäätöksessä on aina tasapainotettava viive ja käyttäjävaatimukset: kuormaa voidaan ohjata edullisemman ja puhtaamman energian alueille vain, jos palvelun latenssi- ja saatavuusrajat sallivat sen [1]. 

Lähde
[1] Jin, X., Zhang, F., Vasilakos, A. V., & Liu, Z. (2016). Green Data Centers: A Survey, Perspectives, and Future Directions (arXiv:1608.00687). arXiv.


## 2. Vihreän datakeskuksen peruselementit ja periaatteet
Vihreä datakeskus on kokonaisuus, jossa IT-kuorma, sähköketju, jäähdytys, rakennus sekä ohjaus ja valvonta suunnitellaan yhtenä järjestelmänä, ja toimintaa johdetaan sovituilla, mitattavilla energia- ja ympäristötunnusluvuilla. 
Vihreän datakeskuksen ratkaisut jäsentyvät neljään koriin: (1) energiatehokkuus IT:ssä, (2) resurssienhallinta, (3) lämpötilanhallinta ja (4) mittarit & monitorointi [4]. Lisäksi modernissa suunnittelussa korostuu ajatus datakeskuksesta “yhtenä tietokoneena” (warehouse-scale computer), jolloin energiatehokkuus ja käytettävyys syntyvät yhtä paljon ohjelmistosta ja orkestroinnista (automaattisesta kuormien ja resurssien ohjauksesta) kuin laitevalinnoista. [1]

2.1 IT-kerros: energiatehokas laskenta ja resurssienhallinta

Tavoite: tuottaa sama palvelutaso pienemmällä energialla ja vähemmällä ylikapasiteetilla.
-Energiatehokkuus (DVFS ja lepotilat): Prosessorien dynaaminen taajuus-/jännitesäätö (DVFS, eli kellotaajuuden ja käyttöjännitteen automaattinen säätö kuorman mukaan) sekä lepotilat/power-down-tilat (eli käyttämättömien ytimien, komponenttien tai jopa koko palvelimen siirtäminen matalatehotilaan) ovat keskeisiä keinoja tehdä kulutuksesta kuormaa vastaavaa (“energy-proportional”). [4]

-Virtualisointi ja konsolidointi: Virtualisointi tarkoittaa, että samalla fyysisellä palvelimella voidaan ajaa useita erillisiä “virtuaalisia palvelimia” (virtuaalikoneita tai kontteja), jolloin sovellukset eivät ole sidottuja yhteen laitteeseen. Konsolidointi tarkoittaa, että nämä kuormat kootaan tarkoituksella harvemmille fyysisille palvelimille niin, että käyttöaste nousee. Kun kuormat ajetaan korkeammalla käyttöasteella harvemmilla palvelimilla, säästyy sekä IT-sähköä että jäähdytystä; samalla voidaan sammuttaa vajaakäytöllä olevia laitteita hallitusti. Tämä kuuluu resurssienhallinnan ytimeen. [4]

-Tehorajoitus (power capping) ja kuormien ohjaus: IT-kuormaa voidaan rajoittaa ja siirtää ajallisesti/paikallisesti sähkön hinnan, uusiutuvan saatavuuden tai lämpötilatilanteen mukaan (orkestrointi + kapasiteettipolitiikat). [4]

2.2 Sähkö: syötöt, UPS, varavoima, jakelu ja häviöiden minimointi

Tavoite: saavuttaa korkea käytettävyys mahdollisimman pienin häviöin ja mitoittaa sähkönsyöttö- ja jakelujärjestelmä kuormitusprofiilin mukaisesti (välttäen “varmuuden vuoksi” -ylimitotusta), siten että ratkaisu tukee asetettuja ympäristötavoitteita.

-Sähkönsyöttö- ja jakeluketjun hyötysuhde. Green IT -viitekehykset korostavat koko sähkönsyöttöketjun häviöiden systemaattista mittaamista ja pienentämistä muuntajilta (jännitetasomuunnokset) UPS-laitteiston kautta PDU-yksiköihin (Power Distribution Unit; sähkönjakeluyksikkö/räkkijakelu) ja lopulta IT-kuormalle (palvelimet, verkko ja tallennus). Tavoitteena on mittaripohjainen johtaminen, jossa häviöt tehdään näkyväksi ja niiden kehitystä seurataan ajassa. [7]

-Varmistusratkaisut vs. energiatehokkuus: Koska N+1- ja 2N-varmistus lisää usein osakuormalla käyviä laitteita ja siten häviöitä. Tämä kasvattaa häviöitä erityisesti silloin, kun järjestelmän kuormitusaste on pitkäkestoisesti matala.  Vaikutus tulee tehdä näkyväksi mittareilla ja kuormaprofiileilla,jotta varmistuksen ja energiatehokkuuden välinen kompromissi voidaan käsitellä eksplisiittisesti. Vihreä toteutus tarkoittaa varmistuksen ja energiatehokkuuden yhteisoptimointia sekä suunnittelussa että operoinnissa [6] . 

-Energiavarastointi ja UPS osana datakeskuksen energianhallintaa. Energiavarastointi (esim. akkuvarasto/BESS) ja UPS (Uninterruptible Power Supply; keskeytymätön virransyöttö) ovat datakeskuksen energianhallinnan ja sähkönsyötön jatkuvuuden keskeisiä toteutuskomponentteja. Energiavarastolla voidaan toteuttaa tehon- ja kuormituksenhallintaa (peak shaving), tukea datakeskuksen paikallisen sähkönjakelun toimintaa (UPS, varavoima ja mahdollinen energiavarasto) sekä parantaa uusiutuvan energian hyödyntämistä ajallisen siirron kautta (ylijäämän varastointi ja myöhempi käyttö) [8].

-Mitoitus ja häviöt: “vihreys” syntyy käyttöprofiilissa. Ympäristötehokkuus alkaa mitoituksesta ja kuormitusprofiilista: sekä UPS- että varastojärjestelmien järjestelmätason hyötysuhde ja omakulutus muodostuvat muunnosketjun häviöistä (tehoelektroniikka, lataus/purkaus) sekä kuormasta riippumattomista perushäviöistä (ohjaus, valvonta, suojaukset ja mahdollinen lämpöhallinta). Ylimitoitus kasvattaa pitkäkestoisen osakuormakäytön todennäköisyyttä, jolloin perushäviöiden suhteellinen osuus kasvaa ja nettotehokkuus heikkenee; samalla myös poistettavan hukkalämmön määrä voi kasvaa. Tämän vuoksi vihreässä suunnittelussa korostuvat kuormitusdataan perustuva mitoitus (tai modulaarinen kapasiteetti) sekä häviöiden minimointi koko suunnitellulla käyttöalueella. [11] [15]

-Energianvarastointitekniikan valinta käyttötarpeen mukaan. Energiavarastointitekniikka valitaan vaaditun keston ja vasteajan perusteella. Lyhyisiin katkottomuustarpeisiin (sekunnit–minuutit) soveltuvat mm. vauhtipyöräratkaisut, joiden vasteaika on millisekuntitasoa ja tyypillinen purku-/latauskesto 20 s–20 min; ominaisuuksiltaan ne sijoittuvat superkondensaattorien ja akkujen väliin. [12] Esimerkiksi MGHPCC-konesalissa (Massachusetts Green High Performance Computing Center) käytetään vauhtipyöräpohjaista UPS:ää generaattorien käynnistymiseen asti, ja ratkaisun yhteydessä korostetaan myös kompromissia: vauhtipyörän valmiustila kuluttaa energiaa, joten varmistus voidaan rajata vain osaan kuormasta energiatehokkuuden ja käytettävyyden tasapainottamiseksi. [6].

Tuntien mittakaavan varakesto ja energian ajallinen siirto. Jos tavoitteena on pidempi varakesto tai energian ajallinen siirto (tuntien mittakaavassa), akkuvarasto on tyypillinen vaihtoehto. Litiumioni-BESS (Battery Energy Storage System) koostuu akustosta sekä ohjaus- ja suojajärjestelmistä ja tehoelektroniikasta, joiden avulla energiaa voidaan varastoida ja syöttää takaisin kuormalle tai sähköverkkoon; tyypillinen purkukesto on usein 1–6 tuntia. Superkondensaattorit soveltuvat puolestaan erityisesti lyhytkestoiseen UPS- ja power quality -tukeen suurille hetkellisille kuormille. [13]

Elinkaariperustelu. “Vihreys” kannattaa perustella myös elinkaarella: elinkaariarvioinneissa litiumioniakkujen ympäristövaikutusten on raportoitu olevan useissa tarkastelluissa vaikutusluokissa pienemmät kuin lyijyakkujen (per toimitettu kWh). Samalla korostuu käyttö­vaiheen sähkön merkitys: lataussähkön päästöintensiteetti (millä sähköllä varasto käytännössä ladataan) vaikuttaa kokonaisvaikutukseen olennaisesti. [14]



2.3 Jäähdytys ja lämpötilanhallinta: ilma, neste, free cooling ja “kuuma–kylmä”

Tavoite: poistaa lämpö mahdollisimman pienellä jäähdytyssähköllä ja hallita luotettavuus–lämpötila-kompromissi.

-Free cooling ja ilmavirtojen hallinta: Pitkä vapaajäähdytyskausi on käytännössä Suomen vakioetu, mutta hyödyt realisoituvat vasta, kun ilmavirrat (kuuma/kylmä-käytävä, tiiveys, ohivirtausten estäminen) ja ohjauslogiikka ovat kunnossa. Lämpötilanhallinta on tutkimuskoosteissa oma pääluokkansa juuri siksi, että se kytkeytyy sekä IT-kuorman sijoitteluun että rakennusratkaisuihin. [4]

-Nestejäähdytys ja immersion (immersiojäähdytys): Nestejäähdytys tarkoittaa, että lämpö siirretään ilmasta nesteeseen lähellä lämmönlähdettä (esim. “direct-to-chip”), jolloin puhaltimien ja ilman kierron tarve pienenee. Immersiojäähdytys on nestejäähdytyksen alalaji, jossa palvelin(komponentit) upotetaan sähköä johtamattomaan nesteeseen. Oppaassa tämä kannattaa esittää valintana erityisesti, kun tehotiheys on korkea tai hukkalämmön hyödyntämiselle halutaan korkeampi lämpötila (helpompi lämmöntalteenotto). (Tämä kohta on tekninen periaatekuvaus; perustele omilla kohdevaatimuksilla ja toimittajadokumenteilla.)

-Käytännön esimerkki “green”-suunnittelusta: MGHPCC-tapaustutkimus kuvaa nimenomaan suunnittelun ja operoinnin yhteisvaikutusta energiatehokkuuteen ja antaa uskottavan referenssikehyksen (mitä mitataan, mitä optimoidaan, miten operointikäytännöt vaikuttavat). [6]

2.4 Rakennus: ilmavirrat, tiiveys, modulaarisuus ja huollettavuus

Tavoite: mahdollistaa energiatehokas jäähdytys ja turvallinen ylläpito koko elinkaaren ajan.

-Datakeskuksen “shell” ja MEP-ratkaisut (sähkö + jäähdytys + tilat) tulee kuvata selkeästi perusoppaassa: tilajaot, huoltotilat, kaapelireitit, tiiveysratkaisut, skaalautuvuus. Data Center Handbook toimii hyvänä runko-ohjeena, koska se jäsentää datakeskuksen suunnittelun rakennuksesta sähköön ja jäähdytykseen sekä operointiin. [3]

-Kun yhdistät tämän “datacenter-as-a-computer” -ajatteluun, saat perustelun sille, miksi rakennus ei ole vain kustannuserä vaan osa suorituskykyä, energiatehokkuutta ja käytettävyyttä. [1]

2.5 Mittarit ja valvonta: PUE, CUE ja jatkuva optimointi

Tavoite: tehdä vihreys todennettavaksi ja ohjattavaksi.
-Tutkimuksissa mittarit ja monitorointi ovat oma pääpilarinsa: ilman jatkuvaa mittausta (IT-kuorma, jäähdytys, sähköketjun häviöt, lämpötilat, uusiutuvan osuus) “vihreys” jää väitteeksi. [4]

-Oppaaseen kannattaa kirjata vähintään: PUE (kokonaisenergiatehokkuus), CUE (hiili-intensiteetti), sekä käytännön mittauspisteet (mistä PUE lasketaan, mitä mitataan PDU/UPS-tasolla ja jäähdytyksessä). [7]

2.6 Verkko (DCN): energiatehokas liikenne ja verkko-tietoinen sijoittelu

Tavoite: välttää tilanne, jossa “vihreä IT ja jäähdytys” tehdään, mutta verkko syö hyödyt.
-Vihreän datakeskuksen verkko ei ole vain kapasiteettikysymys: tutkimuskoosteet nostavat esiin energiatehokkaat topologiat, linkkien/porttien dynaamisen ohjauksen sekä verkko-tietoisen kuormien sijoittelun. [2]

2.7 Uusiutuva integraatio ja mikroverkot (valinnainen moduuli)

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


## 3. Datakeskuksen elinkaaren vaiheet

1) Esiselvitys (tarve, vaihtoehdot, vihreän tason tavoitteet)

Tässä vaiheessa tehdään “lukitsevat” päätökset siitä, miksi datakeskus tehdään, mitä palvelua tuotetaan (SLA, kuormaprofiili, kapasiteetin kasvu) ja miten vihreys mitataan ja johdetaan. Jos energiatehokkuus-, CO₂- ja hukkalämpötavoitteita ei päätetä tässä, ne jäävät helposti myöhemmin “raportoinniksi” eikä suunnittelua ohjaavaksi vaatimukseksi. [1–3]

Keskeiset kysymykset (rajaus):

Mikä on kuormaprofiili (huiput, vaihtelu, kasvu) ja SLA—mitä voidaan joustaa ja mitä ei? [5]

Mitä “vihreä taso” tarkoittaa: PUE/WUE, CO₂/palveluyksikkö, uusiutuvan energian osuus, hukkalämmön hyödyntämisen tavoite? [3,6]

Miten elinkaari rajataan: huomioidaanko myös rakentaminen, hankinnat ja modernisoinnit (ei vain käyttö)? [1,7]

Minimitoimet (tee vähintään):

Kirjaa kuormaprofiili ja SLA sekä kasvuskenaariot.

Sovi tavoitemittarit ja laskentasäännöt (PUE/WUE/CO₂/palveluyksikkö + hukkalämpö). [3,6]

Tuotokset:

Esiselvitysraportti + tavoitetaso (energia, CO₂, hukkalämpö) + vaihtoehtoskenaariot (sijainti/energia/lämpö) + päätös etenemisestä. [2–3]

2) Suunnittelu (sijainti, kapasiteetti, perusratkaisut)

Suunnittelussa muutetaan tavoitteet arkkitehtuuriksi ja varmistetaan, että myöhemmin voidaan oikeasti mitata ja optimoida: jäähdytys, sähkö, kuorma ja hukkalämpö eivät saa jäädä “mustiksi laatikoiksi”. [4,8]

Keskeiset kysymykset (rajaus):

Sijainti ja energia/lämpö: miten sähkö ja lämpöverkot (hukkalämpö) rajaavat toteutusta? [9,10]

Kapasiteetin kasvumalli: rakennetaanko modulaarisesti vai ylikapasiteettina (vajaakäyttöriski)? [5]

Mitattavuus: mitä mitataan, mistä, millä tarkkuudella ja miten data käytetään ohjauksessa? [6,8]

Perusratkaisut: jäähdytyskonsepti, ilmavirrat/layout, sähköketju, automaatio, verkon hallittavuus. [4,8,11]

Minimitoimet (tee vähintään):

Suunnittele mittauspisteet ja rajapinnat niin, että PUE/WUE/CO₂ voidaan laskea luotettavasti ja ohjaus on mahdollinen. [6,8]

Valitse jäähdytys- ja sähköketju, jotka toimivat myös osakuormilla ja mahdollistavat säätölogiikan. [4,8]

Tuotokset:

Konseptisuunnitelma + mittaus- ja ohjausarkkitehtuuri + vaiheistus (modulaarinen kasvu) + lämpöintegraation periaate. [8–10]

3) Rakentaminen (toteutus periaatteiden pohjalta)

Rakentamisen “vihreä ydin” on varmistaa, että suunniteltu mitattavuus ja ohjattavuus toteutuvat käytännössä: mittarit, lokit ja rajapinnat tulevat fyysisesti ja loogisesti paikoilleen. Lisäksi ilmavirtojen kannalta pienetkin toteutusvirheet (läpiviennit, tiiveys, kaapelointi) voivat lisätä jäähdytyshukkaa. [4,8]

Keskeiset kysymykset (rajaus):

Onko mittausjärjestelmä (anturit, energiamittarit, virtausmittaus, data-alusta) asennettu suunnitellusti ja kalibroitu? [6,8]

Vastaavatko ilmavirrat ja tilaratkaisut (containment, tiiveys) suunnitelmaa? [4,8]

Onko rajapinnat ja lokitus rakennettu niin, että operointi voi tehdä “muutos → vaikutus” -todentamisen? [6]

Minimitoimet (tee vähintään):

As-built-dokumentaatio: mittauspisteet, kytkennät, rajapinnat, lokit, setpointien hallinta.

Laadunvarmistus ilmavirroille/tiiveydelle ja mittauksen toimivuudelle. [4]

Tuotokset:

As-built + testisuunnitelma käyttöönottoon + hyväksytty mittaus- ja lokitusarkkitehtuuri. [8]

4) Käyttöönotto (testaus, ensimmäiset mittaukset)

Käyttöönotossa tehdään baseline-mittaukset ja asetetaan vertailutaso tavoitteisiin: miten PUE/WUE/CO₂ käyttäytyvät osakuormilla ja nimelliskuormalla, missä on kuumia pisteitä, ja miten automaatio reagoi. Tämä on kriittistä, koska ilman baselinea myöhempi optimointi jää arvailuksi. [12–13]

Keskeiset kysymykset (rajaus):

Onko baseline mitattu kuormatasoittain (osakuorma → suunnittelukuorma)? [12]

Onko mittausdatan laatu riittävä (luotettavuus, aikaleimat, datakatkokset)? [6]

Onko ohjausstrategiat otettu käyttöön “alusta asti” (ei käsiohjauksen vakiintumista)? [6,12]

Minimitoimet (tee vähintään):

Kuormitustestit + lämpötilaprofiilien kartoitus + baseline-raportti. [12]

Hyväksytyt mittarilaskennat (PUE/WUE/CO₂) ja hälytysrajat. [6,12]

Tuotokset:

Commissioning-raportti: baseline, poikkeamat, korjaavat toimet ja tuotantokriteerit. [12]

5) Käyttö ja operointi (normaali arki konesalissa)

Operointi on elinkaaren pisin vaihe ja suurin kumulatiivisten hyötyjen lähde: jatkuva mittaus, PUE/CO₂-seuranta ja häiriöiden tunnistus. Tavoite ei ole “kerran viritetty”, vaan jatkuvan parantamisen malli: mittaa → analysoi → muutos → vaikutus → vakiointi. [6,14–15]

Keskeiset kysymykset (rajaus):

Miten kuormaa hallitaan (konsolidointi, ajoitus), jotta käyttöaste nousee ja turhaa kapasiteettia voidaan hiljentää? [5,8]

Miten jäähdytys ohjataan mittareilla (setpointit, lämpötilaprofiilit, osakuormat)? [4,10,16]

Miten verkon energiatehokkuutta parannetaan (energiamoodit, kuormaan sopeutus), jos relevanttia? [11]

Miten uusiutuvat/varastointi/hukkalämpö kytketään operointiin (jos käytössä)? [9,17–18]

Minimitoimet (tee vähintään):

Jatkuva mittaus ja raportointi: PUE/WUE/CO₂ + poikkeamien käsittely ja selkeä omistajuus. [6,14]

Hälytyslogiikka ja trendiseuranta (häiriöiden tunnistus ennen SLA-vaikutusta). [6]

Tuotokset:

Operointikäytännöt, mittaritaulu (dashboard), säännöllinen energiatehokkuuskatselmus ja dokumentoitu muutoshallinta. [6]

6) Modernisointi ja kapasiteetin laajennus

Tässä vaiheessa päätetään, mitä kannattaa uusia energiatehokkuuden ja kapasiteetin kannalta sekä hyödynnetään historiadataa ja (tarvittaessa) malleja päätöksenteon tukena. Datakeskus elää “sukupolvissa”, ja väärin vaiheistettu refresh voi kasvattaa hetkellistä energiantarvetta ja heikentää optimointia. [5,4]

Keskeiset kysymykset (rajaus):

Mitkä komponentit ovat pullonkauloja (jäähdytys, sähköketju, automaatio, IT) ja mikä on vaikutus PUE/CO₂:een? [4,6]

Miten päivitys vaiheistetaan niin, ettei synny pitkäaikaista vajaakäyttöä tai riskipiikkiä? [5]

Miten varmistetaan “muutos → mitattu vaikutus” (ennen/jälkeen)? [6]

Tarvitaanko elinkaarimallinnusta päästöjen arviointiin (erityisesti isoissa muutoksissa)? [19,7]

Minimitoimet (tee vähintään):

Jokaiselle muutokselle: tavoite, toteutus, ennen/jälkeen mittaus ja päätös vakioinnista. [6]

Päivitetty kapasiteettitiekartta ja elinkaaritavoitteiden tarkistus. [5]

Tuotokset:

Modernisointisuunnitelma + jälkianalyysi + päivitetty mittaristo ja baseline. [6]

7) Purku ja elinkaaren loppu (kiertotalous)

Elinkaaren lopussa yhdistyvät tietoturva ja kiertotalous: data pitää poistaa palauttamattomasti, ja laitteet ohjata uudelleenkäyttöön tai kierrätykseen hallitusti. Samalla kerätään opit seuraavaan hankkeeseen: mikä toimi, mikä ei, ja miten hankintavaatimuksia parannetaan (modulaarisuus, kierrätettävyys, dokumentointi). [20–22]

Keskeiset kysymykykset (rajaus):

Miten mediasanitaatio toteutetaan ja todennetaan (HDD/SSD, menetelmä median ja riskin mukaan)? [20]

Mitkä komponentit uudelleenkäytetään, mitkä kierrätetään, ja miten haitalliset aineet käsitellään? [21–22]

Miten opit viedään takaisin esiselvitykseen ja suunnitteluun (P3: kiertotalousvaatimukset)? [21–22]

Minimitoimet (tee vähintään):

Dokumentoitu sanitointi + todistusaineisto + jäljitettävä materiaalivirta. [20–22]

Tuotokset:

Purkuraportti: sanitointitodisteet, uudelleenkäyttö-/kierrätysaste, toimittajaraportointi sekä “opit seuraavaan hankkeeseen”. [20–22]

Lähteet (APA, numerointi)

[1] UNEP DTU Partnership. (2020). Environmental sustainability of data centres: A need for a multi-impact and life-cycle approach.

[2] Schneider Electric – Data Center Science Center. (2015). Fundamentals of Managing the Data Center Life Cycle for Owners.

[3] Uddin, M., & Rahman, A. A. (2012). Energy efficiency and low carbon enabler green IT framework for data centers considering green metrics. Renewable and Sustainable Energy Reviews, 16(6), 4078–4094.

[4] Geng, H. (Ed.). (2014). Data Center Handbook. John Wiley & Sons.

[5] Barroso, L. A., Clidaras, J., & Hölzle, U. (2013). The Datacenter as a Computer: An Introduction to the Design of Warehouse-Scale Machines (2nd ed.). Morgan & Claypool.

[6] Sharma, P., Pegus II, P., Irwin, D. E., Shenoy, P., Goodhue, J., & Culbert, J. (2017). Design and operational analysis of a green data center. IEEE Internet Computing, 21(4), 16–24.

[7] Whitehead, B., Andrews, D., & Shah, A. (2015). The life cycle assessment of a UK data centre. International Journal of Life Cycle Assessment, 20, 332–349. https://doi.org/10.1007/s11367-014-0838-7

[8] Lawrence Berkeley National Laboratory. (2025). Best Practices Guide for Energy-Efficient Data Center Design.

[9] Liikenne- ja viestintäministeriö. (2020). The ICT sector, climate and the environment (Publications of the Ministry of Transport and Communications 2020:14).

[10] Oró, E., Depoorter, V., Garcia, A., & Salom, J. (2015). Energy efficiency and renewable energy integration in data centres: Strategies and modelling review. Renewable and Sustainable Energy Reviews, 42, 429–445. https://doi.org/10.1016/j.rser.2014.10.058

[11] Bilal, K., Malik, S. U. R., Khalid, O., Hameed, A., Alvarez, E., Wijaysekara, V., … Khan, S. U. (2014). A taxonomy and survey on green data center networks. Future Generation Computer Systems, 36, 189–208.

[12] Shehabi, A., Smith, S., Sartor, D., Brown, R., Herrlin, M., Koomey, J., ... & Lintner, W. (2016). United States Data Center Energy Usage Report. Lawrence Berkeley National Laboratory.

[13] Masanet, E., Shehabi, A., Lei, N., Smith, S., & Koomey, J. (2020). Recalibrating global data center energy-use estimates. Science, 367(6481), 984–986. https://doi.org/10.1126/science.aba3758

[14] Zhang, Q., Cheng, L., & Boutaba, R. (2021). Cloud data centers: Energy efficiency and sustainable design. ACM Computing Surveys, 54(7), 1–36. https://doi.org/10.1145/3453154

[15] Jin, X., Zhang, Y., Vasilakos, A. V., & Liu, Z. (2016). Green Data Centers: A Survey, Perspectives, and Future Directions (arXiv:1608.00687).

[16] Pierson, J.-M., Baudic, G., Caux, S., Celik, B., Costa, G., Grange, L., … Varnier, C. (2019). DATAZERO: Datacenter with zero emission and robust management using renewable energy. IEEE Access.

[17] Vanderbauwhede, W., & Wadenstein, M. (2025). Life Cycle Analysis for Emissions of Scientific Computing Centres. arXiv. https://doi.org/10.48550/arXiv.2506.14365

[18] National Institute of Standards and Technology. (2014). NIST Special Publication 800-88 Revision 1: Guidelines for Media Sanitization.

[19] Li, J., Zeng, X., Chen, M., Ogunseitan, O. A., & Stevels, A. (2015). Control-Alt-Delete: Rebooting solutions for the e-waste problem. Environmental Science & Technology, 49(12), 7095–7102. https://doi.org/10.1021/es5053009

[20] Baldé, C. P., Forti, V., Gray, V., Kuehr, R., & Stegmann, P. (2017). The Global E-waste Monitor 2017: Quantities, Flows, and Resources. United Nations University, ITU, ISWA.


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



