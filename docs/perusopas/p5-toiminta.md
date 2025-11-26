# P5 – Datakeskuksen toiminta: sähköstä palveluksi ja takaisin lämmöksi

Tavoite: kuvata, miten energia kulkee datakeskuksessa vaiheesta toiseen – sähköverkosta palvelimille, verkoon ja jäähdytykseen, edelleen hukkalämmöksi ja lopulta takaisin hyötykäyttöön. Luku vastaa M4-moduulia: sähkö → palvelimet → verkko → jäähdytys → hukkalämpö → mittaus.

## P5.1 Sähkönsyöttö ja virranjakelu

Datakeskuksen toiminta alkaa sähkön saannista. Tyypillinen sähköketju etenee seuraavasti:

1. **Sähköverkko ja muuntajat**  
   Datakeskus liitetään paikalliseen jakelu- tai kantaverkkoon. Korkeajännite muunnetaan datakeskuksen tarvitsemalle tasolle muuntajilla (esim. 110/20 kV → 400 V).

2. **Pääkeskus ja UPS-järjestelmät**  
   Sähkö johdetaan pääkeskuksen kautta keskeytymättömille virtalähteille (UPS), jotka tasoittavat jännitevaihtelut ja turvaavat sähkönsaannin lyhyissä katkoksissa. UPS-laitteet käyttävät akkuja tai muita energian varastointiratkaisuja.

3. **Jakelukeskukset ja PDU-yksiköt**  
   UPS-laitteilta sähkö jaetaan edelleen konesalin jakelukeskuksiin ja **PDU-yksiköihin** (Power Distribution Unit), jotka syöttävät virtaa palvelinkaappeihin. PDU:issa voidaan mitata virran kulutusta kaappitasolla.

4. **Varavoima**  
   Pidemmissä sähkökatkoissa varavoimajärjestelmät (esim. diesel- tai kaasugeneraattorit) käynnistyvät automaattisesti. UPS-laitteet pitävät järjestelmät käynnissä siihen saakka, kunnes generaattori on noussut kuormaan.

Päivittäisessä toiminnassa sähkönsyöttöä valvotaan jatkuvasti: jännite, virta, lämpötila ja kuormitus seurataan, jotta mahdollisiin häiriöihin voidaan reagoida nopeasti.

## P5.2 Jäähdytys ja lämpötilanhallinta

Palvelimet muuttavat sähkön lämmöksi, joka on poistettava luotettavasti. Jäähdytysjärjestelmä huolehtii siitä, että:

- palvelinsalin **lämpötila ja ilmankosteus** pysyvät asetetuissa rajoissa (setpointit)  
- ilmavirrat ohjataan **kylmien ja kuumien käytävien** mukaisesti  
- jäähdytysjärjestelmän oma energiankulutus pysyy mahdollisimman pienenä.

Tyypillisiä ratkaisuja ovat:

- **Ilmajäähdytys**, jossa kylmä ilma puhalletaan palvelimien etupuolelle ja kuuma ilma kerätään takaa pois.  
- **Nestejäähdytys**, jossa lämpö siirretään suoraan nesteeseen (esim. rack- tai prosessorikohtaiset ratkaisut), mikä mahdollistaa suuremman tehopakon pienemmällä ilmavirralla.  
- **Vapaajäähdytys**, jossa hyödynnetään ulkoilmaa tai viileää vettä silloin, kun ulkolämpötila on matala.

Järjestelmä toimii automaattisesti: anturit mittaavat lämpötilaa ja ilmankosteutta, ja ohjausjärjestelmä säätää puhaltimien nopeuksia, venttiilejä ja pumppuja asetettujen arvojen perusteella.

## P5.3 Palvelimet ja tallennus

Palvelimet ja tallennuslaitteet muuttavat sähkön **digitaalisiksi palveluiksi** – verkkosivuiksi, sovelluksiksi ja tietokannoiksi. Ne kuluttavat suurimman osan datakeskuksen IT-energiasta.

### P5.3.1 Fyysiset palvelimet

Fyysiset palvelimet ovat räkkeihin asennettuja laitteita, joissa on:

- prosessorit (CPU/GPU)  
- keskusmuisti  
- paikallinen tallennus ja verkkoliitännät.

Palvelimet asennetaan tyypillisesti standardiräkkeihin (esim. 42U), ja niiden tiheys (kW/räkki) vaikuttaa suoraan sekä sähkönsyötön että jäähdytyksen mitoitukseen. Kuormanhallinta ja virransäästöominaisuudet (esim. prosessorien virranhallinta) ovat tärkeä osa energiatehokkuutta.

### P5.3.2 Virtuaalipalvelimet

Yhä useampi työkuorma ajetaan **virtuaalipalvelimilla** tai konteilla. Yksi fyysinen palvelin voi ajaa kymmeniä tai satoja virtuaalikoneita, jolloin:

- laitteistoa voidaan hyödyntää tehokkaammin  
- kuormaa voidaan siirtää palvelimelta toiselle tarpeen mukaan  
- kapasiteettia voidaan kasvattaa ohjelmallisesti ilman välitöntä uusien laitteiden hankintaa.

Hyvä virtualisointialusta auttaa pitämään palvelimet mahdollisimman **täydessä mutta turvallisessa kuormassa**, jolloin turhaa energian käyttöä tyhjäkäynnillä voidaan vähentää.

### P5.3.3 Tallennusratkaisut

Tallennus voi perustua:

- palvelimien omiin levyihin  
- keskitettyihin tallennusratkaisuihin (SAN/NAS)  
- ohjelmisto- tai pilvipohjaisiin tallennusratkaisuihin.

Tallennusjärjestelmät mitoitetaan suorituskyvyn, kapasiteetin ja saatavuuden tarpeen mukaan. SSD-levyt ja tiered storage -ratkaisut voivat parantaa sekä suorituskykyä että energiatehokkuutta.

## P5.4 Verkko ja yhteydet

Verkko ja yhteydet muodostavat polun käyttäjän laitteen ja datakeskuksen välillä. Päivittäisessä toiminnassa verkko:

- välittää **palvelupyynnöt** internetistä tai yksityisverkoista palvelimille  
- palauttaa vastaukset käyttäjille mahdollisimman pienellä viiveellä  
- huolehtii siitä, että liikenne on **redundanttia ja suojattua**.

Tärkeimmät tekijät:

- riittävä **runkokapasiteetti** datakeskuksen sisällä (switchit, reitittimet, optiset linkit)  
- useat **operaattorit ja fyysisesti erilliset reitit**, jotta vikatilanteet eivät katkaise yhteyksiä  
- kuormantasainratkaisut (load balancerit), jotka jakavat liikenteen palvelimille tasaisesti.

Verkkolaitteiden kuormaa ja virrankulutusta seurataan samalla tavoin kuin palvelimien, ja energiatehokkaat konfiguraatiot (esim. linkkien nopeuden ja määrän säätö kuorman mukaan) tukevat vihreää toimintaa.

## P5.5 Lämmöstä hukkalämmöksi ja hyötykäyttöön

Palvelimissa kulutettu sähkö muuttuu lähes kokonaan lämmöksi. Vihreässä datakeskuksessa tämä **hukkalämpö** pyritään ottamaan talteen ja hyödyntämään:

- Lämpö kerätään jäähdytysjärjestelmän nesteeseen tai ilmaan.  
- **Lämmönvaihtimet** siirtävät lämmön kaukolämpöverkkoon tai erilliseen lämmitysjärjestelmään.  
- **Lämpöpumput** nostavat tarvittaessa lämpötilaa, jotta se sopii rakennusten tai prosessien lämmitykseen.

Esimerkkejä hyötykäytöstä:

- asuin- ja toimistorakennusten lämmitys  
- uimahallit, kasvihuoneet tai muu lämpöä tarvitseva toiminta  
- teollisuusprosessien esilämmitys.

Jos hyötykäyttöä ei ole saatavilla, lämpö johdetaan hallitusti ympäristöön (esim. meriveteen tai ilmaan) voimassa olevien ympäristönormien mukaisesti – mutta vihreän datakeskuksen tavoitteena on, että **mahdollisimman suuri osa lämmöstä päätyy korvaamaan muuta energiantuotantoa**.

## P5.6 Energian kulutus, mittaus ja hukkalämmön hyödyntäminen

Jotta energiatehokkuutta ja hukkalämmön hyödyntämistä voidaan parantaa, datakeskuksessa tarvitaan **automaattinen ja kattava mittausjärjestelmä**.

### Mittaus ja valvonta

Tyypillisesti käytössä ovat:

- **BMS- tai DCIM-järjestelmä** (Building Management System / Data Center Infrastructure Management), joka kerää mittaustietoa sähköstä, jäähdytyksestä, lämpötiloista ja laitteiden tilasta.  
- älykkäät mittarit UPS-laitteissa, PDU-yksiköissä, pumppupiireissä ja jäähdytyskoneissa.  
- anturit, jotka mittaavat palvelinsalin lämpötilaa, ilmankosteutta ja paine-eroja.

Järjestelmät tuottavat reaaliaikaista tietoa esimerkiksi:

- datakeskuksen kokonaisenergiankulutuksesta  
- IT-laitteiden kulutuksesta  
- jäähdytysjärjestelmän ja pumppujen kulutuksesta  
- hukkalämmön talteenoton tehokkuudesta (esim. kW tai MWh siirrettynä lämpöverkkoon).

Mittaus mahdollistaa myös keskeisten tunnuslukujen laskennan, kuten:

- **PUE (Power Usage Effectiveness)**  
- **ERF (Energy Reuse Factor)** ja **REF (Renewable Energy Factor)**  
- vedenkulutukseen liittyvät tunnusluvut (esim. WUE).

### Automaattinen optimointi

Kun mittausdataa kertyy riittävästi, sitä voidaan hyödyntää:

- hälytysten ja raja-arvojen määrittelyyn (ylikuumeneminen, poikkeava kulutus)  
- **tekoäly- ja data-analytiikkapohjaiseen optimointiin**, joka säätää jäähdytystä, kuormanjakoa ja varavoimaa kulloisenkin tilanteen mukaan  
- hukkalämmön hyötykäytön suunnitteluun ja laskennalliseen kannattavuusarvioon.

Näin energia ei ole vain kustannus, vaan aktiivisesti johdettu resurssi: tavoitteena on **pienentää kulutusta, lisätä uusiutuvan energian osuutta ja hyödyntää mahdollisimman suuri osa syntyvästä lämmöstä**.

## P5.7 Ketjun kokonaiskuva: sähkö → palvelin → lämpö

Datakeskuksen päivittäistä toimintaa voidaan tarkastella yhtenä ketjuna:

1. **Sähkö** saapuu verkosta muuntajien ja UPS-järjestelmien kautta palvelinkaappeihin.  
2. **Palvelimet ja tallennus** käyttävät sähköä laskentaan ja datan käsittelyyn. Tuloksena syntyy digitaalisia palveluita käyttäjille.  
3. Sähkö muuttuu **lämmöksi**, joka kerätään jäähdytysjärjestelmään.  
4. **Jäähdytys** pitää palvelinsalin lämpötilan ja kosteuden hallittuna, samalla siirtäen lämmön eteenpäin.  
5. Lämpö ohjataan **hukkalämpönä hyötykäyttöön** tai poistetaan ympäristöön hallitusti.  
6. Koko ketjua ohjataan **mittauksen, valvonnan ja analytiikan** avulla, jotta energiatehokkuus ja ympäristövaikutukset pysyvät tavoitteiden mukaisina.

Kun jokainen ketjun osa suunnitellaan ja operoidaan vihreiden periaatteiden mukaisesti, datakeskus voi tuottaa kriittisiä digitaalisia palveluita samalla, kun sen energiankulutus ja hiilijalanjälki pysyvät mahdollisimman pieninä.

