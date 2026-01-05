## Johdanto vihreään datakeskukseen

Tämä perusopas syventää itseopiskelumateriaalia ja etenee sen rakenteen mukaisesti: johdannon jälkeen opas vastaa kappaleiden 1–6 (M1–M6) teemoja. Vihreän datakeskuksen ymmärtämiselle luodaan perusta tarkastelemalla ensin perinteisen datakeskuksen energia- ja laitemitoitusta, koska mitoitusketju (kuorma → kapasiteetti → IT-teho → sähkönsyöttö ja jäähdytys) selittää datakeskuksen sähköenergiatarpeen muodostumisen. 

Tämän jälkeen johdannossa määritellään vihreä datakeskus ja sen tavoitteet tutkimuskirjallisuuden avulla sekä tiivistetään, mitä vihreys tarkoittaa käytännön päätöksinä. Luvut 2–7 käsittelevät sijaintiperusteet, peruselementit ja periaatteet, elinkaaren ja toiminnan vaiheet, energian kulutuksen ja uudelleenkäytön sekä energiatehokkuuden mittaamisen. Jokainen keskeinen väite ankkuroidaan lähteisiin, jotta lukija voi arvioida johtopäätöksiä ja soveltaa niitä omaan tilanteeseensa.


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




# Perusopas vihreän datakeskuksen rakentamiseksi Suomessa
## 2. Rakentamisen syyt ja sijaintipäätökset
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


## 3. Vihreän datakeskuksen peruselementit ja periaatteet
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

---

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

---

## 4.1) Tarvekartoitus ja esiselvitys

### Miksi?
Tässä vaiheessa päätetään 70–80 % myöhemmistä kustannus- ja energiatehokkuusominaisuuksista, koska valitaan kuormaprofiili, palvelutasot, sijainti ja tavoitearkkitehtuuri. Väärä mitoitus näkyy joko ylikapasiteettina (pysyvät perushäviöt, turha infra) tai alikapasiteettina (SLA-riski, kiireiset laajennukset). [1][2][3]

### Mitä tehdään (sisältö, ei vain lista)?
- **Kuorman ja palvelutason määrittely:** erottele IT-kuorma, jäähdytyskuorma ja infrastruktuurikuorma; määritä kuormaprofiili (päivä/viikko/kausi) eikä vain “maksimikilowatit”. [3][13]  
- **Sijainnin arviointi (Suomi):** vapaajäähdytyskausi, sähkön saatavuus ja liityntäkapasiteetti, kuituyhteydet, hukkalämmön hyödyntäminen (kaukolämpöverkko / prosessilämpö), sekä maankäyttö ja lupaympäristö. [3][11]  
- **Ratkaisuvaihtoehdot:** oma / colocation / pilvi / hybridi – vertaile todellista ohjattavuutta (mittaus, energialähteet, hukkalämpö) ja vastuujakoa (kuka vastaa mittareista ja raportoinnista). [1][2][3]  
- **Vihreät tavoitteet ja mittarit:** aseta KPI:t (PUE, WUE, CUE, uusiutuvan osuus, hukkalämmön hyödyntämisaste) ja tee niistä projektin “sopimus”: niitä vasten hyväksytään suunnitelmat ja käyttöönotto. [2][3][11]  

### Tuotokset (deliverables)
Minimissään:
- **Vaatimusmäärittely (Requirements):** kapasiteetti, SLA, redundanssitaso, laajennuspolku, IT-arkkitehtuuriperiaatteet. [1][3]  
- **Vihreä tavoitekehys:** KPI-tavoitteet + mittausperiaatteet + raportointitarpeet (myös EU-tasolle). [2][5][6][7]  
- **Feasibility + TCO/LCA-suunta:** kustannus- ja ympäristövaikutusten suunta-arvio vaihtoehdoille. [2][17]  

### Jos vaihe ohitetaan / tehdään heikosti
- Koko hanke voi “lukittua” väärään kokoon → myöhemmin rakennetaan kiireessä lisää (kalliimpaa, epäoptimoitua) tai pyöritetään vajaakuormalla (häviöt).  
- KPI:t jäävät “toiveiksi” → suunnittelussa ei ole tarkkaa mittaus- ja todentamispolkua, jolloin käyttöönotossa ei tiedetä, saavutettiinko vihreys oikeasti. [2][3]  

---

## 4.2) Suunnittelu

### Miksi?
Suunnittelussa päätetään, miten vihreys toteutuu konkreettisina teknisinä ratkaisuina ja ennen kaikkea mitattavuutena (measurement & verification). Tämä vaihe tuottaa rakennusvaiheen “ohjekirjan”: jos dokumentaatio on puutteellinen, rakennusvaiheessa tehdään tulkintoja – ja tulkinnat maksavat. [1][3][4]

### Mitä tehdään 

#### A) Mittauspisteet ja todentaminen (M&V)
- Määritä PUE/WUE/CUE-laskennan rajat: mikä lasketaan “IT load” vs “facility load”; missä kohtaa mitataan sähkö (pääkeskus, UPS-lähtö, PDU/rack). [3][13]  
- Määritä sensorien tarkkuusluokat, aikaleimavaatimukset ja data-ketju (BMS/DCIM), jotta mittausdata kelpaa päätöksentekoon ja raportointiin. [3][6][7]  
---

**Liite A:** Mittauspisteiden minimirunko (konkreettinen mittaripistekartta).

---


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

---

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

---

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

---

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

---

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

---

## Tiivis “vihreän onnistumisen” sääntö

- Määritä KPI:t ja mittausrajat esiselvityksessä → ne ohjaavat kaikkea. [2][3]  
- Suunnittelussa tee dokumenteista rakennusvaiheen “totuus” (BoD, mittaussuunnitelma, commissioning). [1][3]  
- Rakentamisessa varmista toteuma + as-built + testaus, muuten operointi on sokkona. [3][12]  
- Operoinnissa optimoi jatkuvasti, muuten vihreys rapautuu. [3][11][12]  

---

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



## 5. Vihreän datakeskuksen toiminta vaiheittan: sähköstä palveluksi ja takaisin lämmöksi

**Tavoite:** kuvata, miten **energia ja tieto** kulkevat vihreässä datakeskuksessa vaiheesta toiseen (sähkö → IT-palvelu → lämpö) ja miten ketju toteutetaan Suomessa niin, että **uusiutuva energia, energiatehokkuus (PUE), hukkalämmön hyödyntäminen, mittaus/raportointi ja jatkuva optimointi** ovat osa normaalia toimintaa. [1–4][6–9]

**Lukijalle käytännön lupaus:** jokaisen alaluvun lopussa on **tuotokset (deliverables)** ja “**Mistä saat tämän?**” -ohje: teetkö itse, tilaatko suunnittelijalta, pyydätkö datakeskusoperaattorilta vai energia-/kaukolämpöyhtiöltä.

---

## P5.1 Sähkönsyöttö ja virranjakelu (verkosta IT-kuormaan)

**Miksi?**  
Datakeskus on **kriittinen sähköjärjestelmä**: toimitusvarmuus (UPS/varavoima) ja energiatehokkuus ratkaistaan yhtä aikaa. Kaikki häviöt (muunto, UPS, jakelu) näkyvät lopulta myös jäähdytyskuormana, koska sähkö päätyy lämmöksi. [6][7] Suomessa vihreys edellyttää lisäksi, että sähkön alkuperä ja päästöt ovat **todennettavissa** ja raportoitavissa. [9]

**Mitä tehdään (sisältö)?**  
1) Määritetään sähköketju (verkko → muuntajat → UPS → jakelu/PDU → räkit) ja 2) tehdään siitä **mitattava**, jotta voidaan erottaa **IT-kuorma** ja **infrastruktuurikuorma** (PUE:n perusta). [2][6][7]  
Samalla varmistetaan, että uusiutuvan sähkön hankinta ja päästöintensiteetin todentaminen kytketään sopimuksiin (ei “jälkikäteen arvioituna”). [9]

**Näin toimit käytännössä (ICT-yrityksen askelpolku):**
- **A. Päätä toteutusmalli (vaikuttaa siihen, mistä saat tuotokset):**
  - *Oma datakeskus*: tilaat suunnittelun ja urakat (sinulla suurin kontrolli mittaukseen).
  - *Colocation / konesalipalvelu*: et rakenna itse, mutta vaadit mittauksen, raportoinnin ja läpinäkyvyyden sopimusehdoiksi.
- **B. Tee työpaketti “Sähkö + mittaus”:** laadi 1–2 sivun vaatimuslista, jossa vaadit mittauspisteet ja raportoinnin ennen laitevalintoja. (Tämä on hankinnan tärkein ohjauskeppi.) [2]
- **C. Pyydä kapasiteetti ja liittymäaikataulu kirjallisena:** Suomen kontekstissa sähköliittymä (MW, aikataulu) on usein kriittinen polku. (Tämä on toteutettavuuden “todiste”.)

**Tuotokset (deliverables) + mistä ne saat?**
- **Sähköketjun arkkitehtuuri + varmistusratkaisut** (single line diagram / SLD, varmistusluokka, UPS- ja generaattorikonsepti). [6][7]  
  - *Mistä saat?* Sähkösuunnittelijalta (kriittinen sähkö), EPC/urakoitsijalta tai colocation-operaattorin teknisestä dokumentaatiosta.
- **Mittauspistekartta sähköketjuun**: kokonaiskulutus (grid-in), UPS sisään/ulos (UPS-häviöt), jakelutasot (esim. PDU/räkki tai ryhmä). [2][6][7]  
  - *Mistä saat?* Suunnittelijalta + mittaus-/automaatiointegraattorilta (DCIM/BMS). Colocationissa: vaadi asiakasraportointiin vähintään IT-energian ja kokonaisenergian erottelu.
- **Raportointivalmius uusiutuvan sähkön ja päästöjen osalta**: todentaminen + laskentaperiaate (mitä todennetaan ja miten). [9]  
  - *Mistä saat?* Sähkönmyyjältä (alkuperätakuu/GoO), operaattorilta tai omasta energiahallinnasta.

**Minimissään**
- Mittaa vähintään: **kokonaisenergia** + **IT-energia** + **UPS sisään/ulos** (häviöt). [2][6][7]

**Jos vaihe ohitetaan / tehdään heikosti**
- PUE ja päästöraportointi jäävät arvailuksi, koska IT- ja infraenergiaa ei voi erottaa; UPS-häviöt jäävät piiloon ja kulutus “lukittuu” vuosiksi. [2][7]

---

## P5.2 IT-palvelu: palvelimet, virtualisointi ja kuormanohjaus (sähkö → laskenta)

**Miksi?**  
Vihreys realisoituu vasta, kun IT-työ tehdään **minimaalisella energialla per palvelu**. Tutkimus korostaa kuorman yhdistämistä (consolidation), energiaproportionaalia laskentaa ja dynaamista sijoittelua, joilla tyhjäkäynti pienenee. [1][2][4]

**Mitä tehdään (sisältö)?**  
- Määritetään **kuormaprofiili** (mitä ajetaan, milloin ja millä SLA:lla).  
- Toteutetaan **virtualisointi/kontit** ja **konsolidointi**, jotta sama kapasiteetti saadaan vähemmällä rautamäärällä. [1][2]  
- Otetaan käyttöön **tehonhallinta** (esim. prosessorien tehonsäätö) ja varmistetaan, että vaikutus näkyy mittauksessa ja lämpökuormassa. [1][2]  
- Suomi-näkökulmasta: pienempi ja tasaisemmin ohjattu kuorma helpottaa myös hukkalämmön hyötykäytön mitoittamista ja parantaa kokonaisvaikutusta. [1][9]

**Näin toimit käytännössä**
- **A. Tee “IT-kapasiteettikuvaus” (1–2 sivua):** palvelut, SLA, kasvu, huiput, kriittiset kuormat.
- **B. Tee “konsolidointipolitiikka”:** milloin tyhjiä solmuja sammutetaan/nukutetaan ja milloin pidetään reservissä.
- **C. Varmista mittausrajapinta:** IT-energian mittaus ja kuormamittarit (käyttöaste, CPU, muistiprofiili) samaan seurantarakenteeseen.

**Tuotokset + mistä ne saat?**
- **Kuormaprofiili + kapasiteettisuunnitelma** (kasvuskenaariot, SLA, varareservi-periaate). [1][4]  
  - *Mistä saat?* Omasta IT-arkkitehtuurista/tuoteomistuksesta; tarvittaessa konsultilta.
- **Kuormanohjauksen periaatteet + mittarointi** (konsolidointi, power-capping, automaation rajat). [1][2]  
  - *Mistä saat?* Alusta-/pilvitiimiltä (VMware/Kubernetes), datakeskusoperaattorilta (jos managed).

**Minimissään**
- Kyky mitata käyttöaste + IT-energia ja välttää pysyvä “varmuuden vuoksi” -ylikapasiteetti. [1][2]

**Jos vaihe ohitetaan / tehdään heikosti**
- Tyhjäkäynti syö energian: kulutus ja jäähdytys kasvavat ilman palvelutason hyötyä. [1][2]

---

## P5.3 Verkko ja yhteydet (palvelu → liikenne → energiankulutus)

**Miksi?**  
Verkko on sekä suorituskyky- että energiakomponentti. Tutkimus korostaa liikenteen mittausta, energiatiloja ja dynaamista ohjausta, joilla kulutusta voidaan pienentää kuorman vaihdellessa. [1][8]

**Mitä tehdään (sisältö)?**  
- Rakennetaan **redundanssi** (eri reitit/operaattorit) mutta vältetään “kaikki aina päällä” -ylikuormitus, jos SLA sallii dynaamiset energiatilat. [8]  
- Otetaan käyttöön energiatehokkaat konfiguraatiot (portit/linkit skaalautuvat kuormaan). [8]  
- Tuodaan verkon mittaus samaan havaintokehykseen kuin IT ja jäähdytys, jotta verkon osuus näkyy päätöksissä. [1][8]

**Näin toimit käytännössä**
- **A. Pyydä verkkosuunnittelulta kaksi näkymää:** (1) SLA/redundanssi, (2) energiatilat ja mittaus.
- **B. Vaatimus sopimuksiin:** saat vähintään laiteryhmäkohtaisen kulutuksen (tai verkon kokonaiskulutuksen) näkyviin.

**Tuotokset + mistä ne saat?**
- **Verkon energiaprofiili (kulutus vs liikenne) + ohjausperiaatteet**. [8]  
  - *Mistä saat?* Verkkosuunnittelijalta / operaattorilta / konesalipalvelun tarjoajalta.

**Minimissään**
- Verkon kulutus ja liikenneprofiili mitataan ja poikkeamat näkyvät (ruuhka/vajaakuorma). [8]

**Jos vaihe ohitetaan / tehdään heikosti**
- Verkko jää “näkymättömäksi kuluksi” ja kasvattaa myös lämpökuormaa ilman ohjausta. [1][8]

---

## P5.4 Jäähdytys ja lämpötilanhallinta (sähkö → lämpö hallintaan)

**Miksi?**  
IT:n käyttämä sähkö muuttuu käytännössä lämmöksi ja on poistettava luotettavasti. Jäähdytys on **säädettävä järjestelmä**: setpointit, ilmavirrat/virtaamat ja ohjauslogiikka määräävät jäähdytyksen energiankulutuksen. [4][6][7]

**Mitä tehdään (sisältö)?**  
- Valitaan jäähdytysarkkitehtuuri, joka hyödyntää Suomen olosuhteita (vapaajäähdytys ja viileä ilmasto). [6][7]  
- Hallitaan ilmavirrat (kuuma/kylmä käytävä, containment, ohivirtaus) ja ehkäistään hotspotit mittaamalla. [7]  
- Kytketään jäähdytys mittaukseen: jäähdytyksen energia ja lämpöteho erotellaan, jotta PUE ja myöhemmin hukkalämpö ovat todennettavia. [2][4][7]

**Näin toimit käytännössä**
- **A. Pyydä HVAC-suunnittelulta “osakuormalupaus”:** miten järjestelmä käyttäytyy 25/50/75/100% kuormilla (tämä ratkaisee vuosikulutuksen). [4][7]  
- **B. Vaadi mittauspisteet jäähdytykseen:** sähkö (pumput, puhaltimet, chillerit) + lämpötilat/virtaamat.
- **C. Vaadi käyttöönotossa säätö ja dokumentointi:** ilman tätä setpointit jäävät “arvauksiksi”.

**Tuotokset + mistä ne saat?**
- **Jäähdytyksen ohjausperiaatteet + mittarit** (lämpötila, ΔT, virtaamat, jäähdytysenergia). [4][7]  
  - *Mistä saat?* LVI/HVAC-suunnittelijalta ja automaatiointegraattorilta (BMS/DCIM).

**Minimissään**
- Lämpötila- ja virtaus/ilmavirta-mittaus sekä kyky säätää kuorman mukaan (ei vakioasetuksilla ympäri vuoden). [4][7]

**Jos vaihe ohitetaan / tehdään heikosti**
- Jäähdytys paisuu suurimmaksi häviöksi; PUE heikkenee ja hukkalämmön hyödyntäminen vaikeutuu, koska lämpötasoja ei hallita. [4][7]

---

## P5.5 Hukkalämmön talteenotto ja hyötykäyttö (lämpö → korvaava energia)

**Miksi?**  
Hukkalämpö on vihreässä datakeskuksessa mahdollisuus tuottaa **lisäilmastohyötyä**: lämpö voi korvata muuta lämmöntuotantoa. Suomessa kaukolämpö ja muut lämmönkäyttökohteet tekevät hyödyntämisestä erityisen relevanttia, ja käytäntöesimerkkejä on koottu sektoritason selvityksiin. [9]

**Mitä tehdään (sisältö)?**  
- Valitaan talteenottokohta ja varmistetaan lämpötaso (ilma/neste), jonka voi siirtää lämmönvaihtimella tai nostaa lämpöpumpulla. [7]  
- Tehdään hyötykäytöstä “oikea toimitusketju”: vastaanottaja (kaukolämpö/kiinteistö/teollisuus), liityntä, sopimus, ja mitattava MWh-siirto. [9]  
- Raportoidaan hyödynnetty lämpö ja sen vaikutus: ilman mittausta hyödyt jäävät väitteiksi. [9]

**Näin toimit käytännössä**
- **A. Ota yhteys paikalliseen kaukolämpö-/energiayhtiöön jo suunnittelussa:** kysy liitynnän ehdot, lämpötaso ja aikataulu (tämä on yhtä “lukitseva” kuin sähköliittymä).  
- **B. Pyydä suunnittelijalta “lämpörajapinta”:** missä kohtaa lämpö otetaan talteen, millä lämpötilalla ja millä teholla.  
- **C. Vaadi mittaus:** siirretty lämpöenergia (MWh) ja jatkuva raportointi.

**Tuotokset + mistä ne saat?**
- **Hukkalämpöliityntä + tekninen ratkaisu + mittaus ja raportointi** (siirretty lämpöenergia). [7][9]  
  - *Mistä saat?* LVI-suunnittelijalta + lämpöyhtiöltä (liityntäehdot) + automaatiointegraattorilta (mittaus).

**Minimissään**
- Lämpöenergian mittaus ja suunnitelma (tai sopimus/LOI) hyötykäytön käynnistämiseksi vaiheittain. [9]

**Jos vaihe ohitetaan / tehdään heikosti**
- Datakeskus voi olla uusiutuvalla sähköllä energiatehokas, mutta yhteiskunnallinen ilmastohyöty jää vajaaksi, jos lämpö poistetaan ympäristöön ilman korvausvaikutusta. [9]

---

## P5.6 Mittaus, johtaminen ja jatkuva parantaminen (ketju ohjattavaksi)

**Miksi?**  
Mittauksen ja palautteen avulla järjestelmä muuttuu ohjattavaksi: “mittaa → analysoi → muutos → todenna vaikutus”. Tämä on vihreän datakeskuksen peruslogiikka: mitataan osat, tunnistetaan kuumat pisteet ja parannetaan mittareiden avulla. [2][4]

**Mitä tehdään (sisältö)?**  
- Rakennetaan end-to-end mittausketju: kokonaiskulutus, IT-energia, UPS-häviöt, jäähdytysenergia, lämpötilat/virtaamat ja hukkalämmön MWh. [2][6][7][9]  
- Johdetaan tunnusluvuilla: PUE perusmittarina ja tarvittaessa muita sovittuja mittareita (esim. uusiutuvan osuus, hukkalämmön hyödyntäminen). [2][9]  
- Otetaan käyttöön poikkeamien hallinta ja optimointi: hälytysrajat, trendit, analytiikka (myös edistyneemmät ohjausmenetelmät, kun data on laadukasta). [1][3][4]

**Näin toimit käytännössä**
- **A. Vaatimus: “mittaus ennen optimointia”:** määritä mittauspisteet ja datan omistajuus jo hankinnassa. [2]  
- **B. Pyydä toimitus: “mittauspisteet → data → laskenta → dashboard”:** ei riitä, että antureita on — ketjun pitää toimia.  
- **C. Tee toimintamalli muutoksille:** jokainen muutos (setpoint, ohjauslogiikka, laitepäivitys) hyväksytään vasta, kun vaikutus näkyy mittareissa. [2][4]

**Tuotokset + mistä ne saat?**
- **Mittaus- ja raportointimalli:** mittauspisteet → data → laskentasäännöt → dashboardit → audit trail. [2][4][7]  
  - *Mistä saat?* DCIM/BMS-toimittajalta ja integraattorilta; tilaajana vaadit tämän toimituseräksi.
- **Jatkuvan parantamisen malli:** mittaa → analysoi → muutos → todenna → vakioi. [2][4]  
  - *Mistä saat?* Operointimallina omalta tuotanto-/infra-tiimiltä tai palveluntarjoajalta.

**Minimissään**
- PUE-laskenta luotettavasti (kokonais + IT) + jäähdytyksen energian seuranta + hukkalämmön MWh-mittaus, jos talteenotto on käytössä. [2][4][7][9]

**Jos vaihe ohitetaan / tehdään heikosti**
- “Vihreys” jää väitteeksi ilman todennusta; optimointi perustuu oletuksiin eikä hyötyjä voi osoittaa luotettavasti. [2][4]

---

## P5.7 Ketjun yhteenveto 

**Miksi?**  
Ketju on kokonaisuus: sähkö, IT, verkko, jäähdytys ja lämpö kytkeytyvät toisiinsa — kaikki sähkö päätyy lopulta lämmöksi. [6][7] Suomessa vihreys konkretisoituu erityisesti uusiutuvan sähkön todennettavuuden, energiatehokkuuden ja hukkalämmön hyötykäytön kautta. [9]

**Mitä tehdään (sisältö)?**  
Käytännön toteutus Suomessa tarkoittaa:  
(i) uusiutuva sähkö todennettuna ja raportoitu, (ii) IT-kuorman energiaproportionaali ohjaus, (iii) mitattu ja ohjattava verkko, (iv) olosuhteita hyödyntävä jäähdytys, (v) hukkalämmön hyötykäyttö, ja (vi) mittaus- ja johtamismalli, joka mahdollistaa jatkuvan parantamisen. [1–4][6–9]

**Tuotokset + mistä ne saat?**
- **Todennettava vihreä toimintamalli**: PUE + uusiutuvan sähkön ja päästöjen raportointi + mitattu hukkalämmön hyötykäyttö. [2][9]  
  - *Mistä saat?* Koostuu edellisten vaiheiden toimituksista; tilaaja varmistaa sopimuksissa.

**Minimissään**
- Mitattu ja raportoitu kokonaisenergia + IT-energia + jäähdytysenergia, sekä todennettava uusiutuvan ja päästöjen laskenta; hukkalämmön hyödyntämisen valmius. [2][7][9]

**Jos vaihe ohitetaan / tehdään heikosti**
- Lopputulos jää osaoptimoinniksi: energiaa kuluu turhaan, lämpö ei korvaa muuta tuotantoa ja todennus puuttuu. [2][4][9]

---

# Lähteet (APA, numerointi)

[1] Jin, X., Zhang, Y., Vasilakos, A. V., & Liu, Z. (2016). *Green data centers: A survey, perspectives, and future directions* (arXiv:1608.00687).

[2] Uddin, M., & Rahman, A. A. (2012). Energy efficiency and low carbon enabler green IT framework for data centers considering green metrics. *Renewable and Sustainable Energy Reviews, 16*(6), 4078–4094.

[3] Pierson, J.-M., Baudic, G., Caux, S., Celik, B., Costa, G., Grange, L., … Varnier, C. (2019). DATAZERO: Datacenter with zero emission and robust management using renewable energy. *IEEE Access*.

[4] Sharma, P., Pegus II, P., Irwin, D. E., Shenoy, P., Goodhue, J., & Culbert, J. (2017). Design and operational analysis of a green data center. *IEEE Internet Computing, 21*(4), 16–24.

[5] *Energy storage techniques, applications, and recent trends – A sustainable solution for power storage*. (n.d.). **Tarkennettava tekijä- ja julkaisudata ennen julkaisemista.**

[6] Barroso, L. A., Clidaras, J., & Hölzle, U. (2013). *The datacenter as a computer: An introduction to the design of warehouse-scale machines* (2nd ed.). Morgan & Claypool.

[7] Geng, H. (Ed.). (2014). *Data center handbook*. John Wiley & Sons.

[8] Bilal, K., Malik, S. U. R., Khalid, O., Hameed, A., Alvarez, E., Wijaysekara, V., … Khan, S. U. (2014). A taxonomy and survey on green data center networks. *Future Generation Computer Systems, 36*, 189–208.

[9] Liikenne- ja viestintäministeriö. (2020). *The ICT sector, climate and the environment – Interim report* (Publications of the Ministry of Transport and Communications 2020:14).



## 6. Energian kulutus ja uudelleenkäyttö
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




