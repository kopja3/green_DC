# P1 – Johdanto vihreään datakeskukseen

Tavoite: selittää lyhyesti, mikä datakeskus on, miksi niistä puhutaan ja mitä vihreys tarkoittaa.

## P1.1 Datakeskus ja sen rooli

Datakeskus on fyysinen laitos, joka sisältää verkotettuja tietokoneita ja laitteita, kuten palvelimia, tallennusjärjestelmiä, reitittimiä ja kytkimiä ja jossa säilytetään, käsitellään ja jaetaan suuria määriä dataa (Kuva 1). Ne toimivat IT-sektorin keskeisenä infrastruktuurina päätehtävänään varmistaa yritysten ja organisaatioiden tärkeiden sovellusten ja tietojen jatkuva saatavuus ja tietoturva [1].

Datakeskusten keskeisin tekninen infrastruktuuri koostuu sähkönjakelujärjestelmästä, mukaan lukien sähkönsyöttö, keskeytymätön virtalähde (UPS) ja varavoimajärjestelmät (esim. dieselgeneraattorit), jotka yhdessä takaavat jatkuvan sähkönsaannin ilman katkoksia, jäähdytysjärjestelmistä ja automaatiojärjestelmistä. Datakeskuksen tuotantoprosessin ydinalue on tietotekniikkajärjestelmäalue, jossa sijaitsevat laitekaapit ja palvelimet. 

<p>
  <img src="./img/p1-kuva1-datakeskus-infra.png"
       alt="Kuva 1. Datakeskuksen infrastruktuuri sisältää sähkönsyötön, jäähdytysjärjestelmän, verkkoyhteydet ja palvelimet."
       style="width:100%;height:auto;">
</p>

*Kuva 1. Datakeskuksen infrastruktuuri sisältää sähkönsyötön, jäähdytysjärjestelmän, verkkoyhteydet ja palvelimet.*

Sähkönsyöttö on kriittinen tekijä datakeskusten infrastruktuurin jatkuvan toiminnan takaamiseksi. Suomessa uudet teollisen mittakaavan datakeskukset on kytketty valtakunnallisen sähköverkko-operaattori Fingrid:in sähköverkkoon, joka vastaa sähköenergian siirrosta ja sähköverkon tasapainon ylläpidosta. 

Datakeskukset mahdollistavat yritysten ja organisaatioiden digitaalisten palveluiden jatkuvan saatavuuden, käsitellen valtavia määriä “palvelupyyntöjä” käyttäjiltä ja sovelluksilta ympäri vuorokauden internetin kautta [Google 1]. 

## P1.2 Palvelupyyntö esimerkkinä toiminnasta

Palvelupyyntö (engl. *request*) tarkoittaa verkkopalveluiden käyttäjiltä tai sovelluksista datakeskukseen saapuvia pyyntöjä, kuten verkkosivujen lataamista, tietokantakyselyitä, tiedostojen lataamista tai muiden verkkopalveluiden hyödyntämistä (Kuva 2).

<p>
  <img src="./img/p1-kuva2-palvelupyynto.png"
       alt="Kuva 2. Palvelupyyntöjen reitti käyttäjiltä datakeskukseen."
       style="width:100%;height:auto;">
</p>

*Kuva 2. Palvelupyyntöjen reitti käyttäjiltä datakeskukseen: pyynnöt eri laitteista kulkevat internetin kautta pilvipalveluihin tai suoraan datakeskukseen, jossa ne käsitellään ja välitetään tarvittaville resursseille.*


## P1.3 Digitalisaatio, energiankulutus ja ympäristöhaaste

Digitalisaation kasvu on tehnyt datakeskuksista modernin infrastruktuurin keskeisen osan, mikä on johtanut niiden määrän ja energiankulutuksen nopeaan kasvuun. Ilmastonmuutoksen torjumiseksi ja kestävän kehityksen saavuttamiseksi on entistä tärkeämpää suunnitella energiatehokkaita ja ympäristöystävällisiä toimintamalleja. 

Tämä opas tarjoaa kokonaisvaltaisen lähestymistavan vihreän datakeskuksen suunnitteluun keskittyen uusiutuviin energialähteisiin, energiatehokkaisiin teknologioihin ja kestäviin toimintamalleihin.

Oppaassa käsitellään muun muassa seuraavia kysymyksiä:

- Miten vähentää energiankulutuksesta johtuvia päästöjä?
- Kuinka uusiutuvat energialähteet, kuten aurinko- ja tuulivoima, integroidaan datakeskusten energiantuotantoon?
- Mitkä teknologiat parantavat energiatehokkuutta sähkönsyötössä, jäähdytyksessä ja laitteistossa?
- Miten tekoäly ja data-analytiikka tukevat energiankulutuksen reaaliaikaista hallintaa?

## P1.4 Mitä vihreä datakeskus tavoittelee. 

Vihreä datakeskus on suunniteltu siten, että sen mekaaniset, sähköiset ja tietojärjestelmät on optimoitu yhdessä maksimaalisen energiatehokkuuden ja vähäisen ympäristövaikutuksen saavuttamiseksi (Gowri, 2005).

P1.4 Vihreän datakeskuksen tutkimuspohjainen määritelmä ja tavoitteet

Tutkimuskirjallisuudessa vihreällä datakeskuksella tarkoitetaan kokonaisuutta, jossa rakennus, sähkönsyöttö, jäähdytys, IT-laitteet ja ohjausjärjestelmät suunnitellaan ja mitoitetaan yhdessä siten, että energiankulutus ja ympäristövaikutukset minimoidaan koko elinkaaren ajan. Tavoitteena ei ole ainoastaan pienentää yksittäisten laitteiden sähkönkulutusta, vaan optimoida koko energiaketju sähkön hankinnasta IT-kuormaan, jäähdytykseen ja hukkalämmön hyödyntämiseen sekä kiertotalouteen perustuvaan materiaalinhallintaan [4]Manganelli ym. 2021. Vihreä datakeskus nähdään siten osana laajempaa energiajärjestelmää, ei erillisenä “sähkönkuluttajana”.

Keskeistä vihreässä datakeskuksessa on energiatehokkuuden, energiamixin ja energian uudelleenkäytön yhteistarkastelu. Tutkimusten mukaan datakeskusten kestävyyttä voidaan parantaa samanaikaisesti kolmella tavalla: 1) pienentämällä kokonaisenergiankulutusta tehokkaiden laitteiden, jäähdytysratkaisujen ja kuormanhallinnan avulla, 2) lisäämällä vähäpäästöisen ja uusiutuvan energian osuutta sähköntuotannossa sekä 3) hyödyntämällä mahdollisimman suuri osa syntyvästä hukkalämmöstä esimerkiksi kaukolämpöjärjestelmissä [4]. EN 50600-4 -standardisarja täydentää tätä näkökulmaa määrittelemällä mittareita (kuten PUE, WUE, CUE ja ERF/REF), joiden avulla datakeskuksen energiatehokkuutta, veden käyttöä, hiilijalanjälkeä ja energian uudelleenkäyttöä voidaan mitata ja vertailla järjestelmällisesti [21] EN 50600-4.

Tässä oppaassa vihreällä datakeskuksella tarkoitetaan näihin tutkimus- ja standardiviitekehyksiin perustuvaa datakeskusta, joka:
käyttää mahdollisimman vähän energiaa suhteessa tarjoamiinsa palveluihin,
hankkii sähkönsä ensisijaisesti vähäpäästöisistä ja uusiutuvista lähteistä,
suunnittelee jäähdytyksen ja hukkalämmön talteenoton osaksi paikallista energiaekosysteemiä,
minimoi vedenkulutuksen ja materiaalien ympäristökuorman sekä
tukee kiertotaloutta laitteiden pitkäikäisyyden, päivitettävyyden ja kierrätettävyyden kautta.
Seuraavissa luvuissa tätä määritelmää avataan käytännön ratkaisujen kautta: ensin sijainnin ja perusratkaisujen tasolla (P2–P3), sitten energiavirran ja hukkalämmön näkökulmasta (P5–P6) sekä lopuksi standardien, mittarien ja sääntelyn tasolla (P7).


### P1.10 Etenemisjärjestys: tarpeesta suunnitteludokumentteihin

Tässä perusoppaassa vihreän datakeskuksen suunnittelu etenee vaiheittain siten, että varhaiset päätökset tuottavat seuraavan vaiheen lähtötiedot. Tarkoitus ei ole valita teknisiä ratkaisuja irrallisesti, vaan lukita ensin tarve, koko, tyyppi ja sijainti, jotta energianhankinta, hukkalämpö, jäähdytys, sähköjärjestelmä ja mittaus voidaan suunnitella yhtenä kokonaisuutena.

#### 1. Tarve

Ensin määritetään, miksi datakeskus rakennetaan. Tässä vaiheessa päätetään myös, onko kyse omasta datakeskuksesta, colocation-ratkaisusta, pilvestä vai hybridimallista. Tarve määrittää myöhemmät painotukset: viive, kapasiteetti, käytettävyys, energiatehokkuus, hukkalämpö ja kustannusrakenne.
**** Miksi tarve määrittää myöhemmät painotukset***
Datakeskuksen käyttötarkoitus määrittää sen, mitä siellä pidetään tärkeimpänä, koska eri valinnat rankaisevat eri tavalla vääristä valinnoista. 

Jos datakeskus rakennetaan esimerkiksi reaaliaikaisiin palveluihin, kuten verkkopalveluihin, maksuliikenteeseen, teollisuuden ohjaukseen tai tekoälyn käyttöpalveluihin, viive ja käytettävyys nousevat keskiöön. Tällöin sijainti, verkkoyhteydet, redundantit järjestelmät ja nopea häiriönsiirto ovat tärkeämpiä kuin aivan alin energiakustannus. Jokainen millisekunti tai käyttökatko näkyy suoraan palvelun laadussa tai liiketoiminnassa. 

Jos taas on tarkoitus ajaa raskasta laskentaa, varmistuksia tai muuta eräajoa, painotus siirtyy kapasiteettiin ja kustannustehokkuuteen. Tällöin pieni lisäviive ei yleensä haittaa, mutta suuri laskentateho, hyvä skaalautuvuus, sähkön hinta ja jäähdytyksen tehokkuus ratkaisevat paljon enemmän. Näissä ympäristöissä tärkeintä on usein, kuinka paljon laskentaa saadaan tuotettua per euro ja per kilowattitunti. Käytettävyyskin riippuu tarpeesta. 

Kriittisissä palveluissa tavoitellaan erittäin korkeaa jatkuvuutta, jolloin rakennetaan enemmän varmistuksia sähköön, verkkoon, jäähdytykseen ja laitteisiin. Se nostaa investointi- ja ylläpitokustannuksia. 

Vähemmän kriittisissä käyttökohteissa voidaan hyväksyä enemmän huoltoikkunoita tai pidempi palautumisaika, jolloin rakenne voi olla kevyempi ja halvempi. Energiatehokkuuden ja hukkalämmön hyödyntäminen korostuvat erityisesti silloin, kun kuorma on suuri ja tasainen. 

Jos datakeskus käy jatkuvasti korkealla teholla, pienikin parannus hyötysuhteessa säästää  paljon rahaa. Samalla hukkalämmöstä voi tulla arvokas sivutuote, jos sen ympärillä on kaukolämpöverkko tai muu lämmön käyttäjä. 

Jos kuorma on epäsäännöllinen tai pieni, hukkalämmön talteenotontoimintalogiikka voi olla paljon heikompi. 

Kustannusrakenne riippuu tästä kaikesta. 

Joissakin datakeskuksissa suurin kysymys on alkuinvestointi: varmistettu sähkö, varavoima, kahdennukset ja korkea turvallisuustaso. 

Toisissa taas tärkein on käyttökustannus: sähkö, jäähdytys, tilatehokkuus ja automaatio. 

Käyttötarkoitus siis ratkaisee, maksetaanko enemmän etupainotteisesti toimintavarmuudesta vai pitkässä juoksussa energiasta ja operoinnista. 

Ydinajatus on tämä: datakeskusta ei voi optimoida yleisesti ”parhaaksi”, vaan tiettyä tehtävää varten parhaaksi. Siksi syy, miksi rakennetaan, määrää myös myöhemmät painotukset viiveen, kapasiteetin, käytettävyyden, energiatehokkuuden, hukkalämmön ja kustannusten välillä.            


**Tuotos:** hankkeen perustelu, käyttötarkoitus, toteutusmalli ja palvelutasotavoite.

#### 2. Koko ja tyyppi

Kun tarve on määritetty, arvioidaan datakeskuksen koko ja tyyppi. Tässä vaiheessa kuvataan työkuorma `L(t)`, palvelutasovaatimukset (SLA/SLO), kapasiteetin tarve sekä se, onko ratkaisu esimerkiksi edge-, enterprise-, pilvi-, HPC- tai AI-painotteinen.

Tavoitteena on johtaa kuormasta kapasiteettitarve ja siitä edelleen IT-tehoprofiili. Tässä vaiheessa ei vielä valita lopullista jäähdytys- tai sähköarkkitehtuuria, vaan muodostetaan niiden mitoituksen lähtötieto.

**Tuotos:** kuormakuvaus `L(t)`, kapasiteettiarvio, palvelutasorajat ja alustava IT-tehoprofiili `P_IT(t)`.

#### 3. Sijainti

Sijainti valitaan vasta, kun tarve, koko ja tyyppi ovat tiedossa. Sijainti määrittää sähköliittymän realistiset vaihtoehdot, verkko- ja viivereunaehdot, uusiutuvan energian hankinnan mahdollisuudet, free cooling -potentiaalin sekä hukkalämmön hyödyntämisen edellytykset.

Sijainti ei ole vain tonttikysymys, vaan energian, liityntöjen ja liiketoimintalogiikan päätös. Tästä syystä se käsitellään ennen varsinaisia teknisiä ratkaisujen valintoja.

**Tuotos:** sijaintipäätös tai sijaintivertailu, jossa on kuvattu sähkö, verkot, liitynnät, free cooling -potentiaali ja hukkalämmön vastaanottajavaihtoehdot.

#### 4. Hukkalämpö osaksi liiketoimintaa

Hukkalämpö arvioidaan jo alkuvaiheessa osana liiketoimintaa, ei vasta teknisenä lisäominaisuutena. Tässä vaiheessa selvitetään, onko kohteella realistinen lämpönielu, kuten kaukolämpöverkko, teollinen vastaanottaja tai muu paikallinen käyttö.

Arvioinnissa tarkastellaan ainakin:
- toimitettavissa oleva lämpöteho ja lämpöenergia
- lämpötilataso
- vastaanottajan sijainti ja liityntäetäisyys
- lämpöpumpun tai muun lämpötilanoston tarve
- sopimus- ja vastuunjakomalli.

Jos hukkalämmön hyödyntäminen on mahdollista, se vaikuttaa jo sijaintiin, järjestelmäarkkitehtuuriin, mitoitukseen ja liiketoimintamalliin.

**Tuotos:** hukkalämmön esiselvitys, rajapintakuvaus, alustava kannattavuus- ja toteutettavuusarvio.

#### 5. Uusiutuvan energian hankinta mukaan heti alkuvaiheessa

Samassa vaiheessa määritetään sähkön hankinnan periaate. Vaihtoehtoja voivat olla esimerkiksi:
- PPA
- oma tuotanto
- alkuperätakuut
- muu todennettava hankintamalli
- näiden yhdistelmä.

Tarkoitus on lukita jo alkuvaiheessa, miten sähkön alkuperä todennetaan ja millä päästökertoimilla käyttöaikaiset päästöt raportoidaan. Tämä ei ole vain raportointikysymys, vaan osa datakeskuksen perusratkaisua.

**Tuotos:** energianhankinnan periaate, todentamistapa ja raportoinnin lähtötiedot.

#### 6. Jos hukkalämpöä tai vahvaa uusiutuvan energian ratkaisua ei saada, free cooling korostuu

Jos sijainnissa ei ole realistista hukkalämmön vastaanottajaa tai uusiutuvan energian hankintaratkaisu jää heikoksi, free cooling nousee keskeiseksi suunnitteluperiaatteeksi. Suomessa tämä on usein luonteva vaihtoehto ilmasto-olosuhteiden vuoksi.

Tässä vaiheessa arvioidaan:
- free cooling -potentiaali
- ulkolämpötilajakauman vaikutus
- valittavan jäähdytysarkkitehtuurin toimintaperiaate
- veden, ilman ja olosuhteiden vaikutus käyttöön
- vaikutus energiankulutukseen ja käyttökustannuksiin.

**Tuotos:** jäähdytysstrategian päälinja ja arvio siitä, missä määrin free cooling toimii kohteessa.

#### 7. Mitoitus

Kun tarve, koko, tyyppi, sijainti, hukkalämpö, sähkön hankinta ja jäähdytysstrategia on määritetty, voidaan tehdä varsinainen mitoitus.

Mitoituksessa johdetaan:
`L(t)` + SLA/SLO → `C_act(t)` + `C_res` → `P_IT(t)` → sähkö- ja jäähdytysinfrastruktuurin mitoitus.

Tässä vaiheessa tiedetään jo riittävästi, jotta voidaan arvioida:
- sähköliittymä ja jakelu
- UPS / varavoima / varmistusperiaate
- jäähdytysteho ja lämpökuorma
- mahdollinen hukkalämmön toimituskapasiteetti
- infrastruktuurin osakuorma- ja hyötysuhdekäyttäytyminen.

**Tuotos:** sähkö- ja jäähdytysjärjestelmän mitoituksen lähtötiedot sekä alustava mitoitusratkaisu.

#### 8. Mittausrajat suunnittelussa, ei jälkikäteen

Mittausrajat määritetään suunnitteluvaiheessa samaan aikaan energian, jäähdytyksen ja hukkalämmön ratkaisujen kanssa. Tällöin voidaan päättää:
- mistä kokonaisenergia mitataan
- mistä IT-energia mitataan
- miten jäähdytyksen sähkö erotellaan
- miten hukkalämmön toimitettu energia todennetaan
- millä laskentasäännöillä KPI:t muodostetaan.

Mittausrajat vaikuttavat suoraan siihen, ovatko PUE-, REF-, ERF-, CER-, CUE- ja WUE-lukuja koskevat raportit vertailukelpoisia ja käyttökelpoisia.

**Tuotos:** mittausrajakuvaukset, mittauspistekartta, KPI-määrittelyt ja raportointisäännöt.

#### 9. Suunnitteludokumentit

Edellisten vaiheiden tuloksena syntyvät suunnitteludokumentit, joilla hanke voidaan viedä tekniseen suunnitteluun, hankintaan ja toteutukseen.

Näitä ovat vähintään:
- tarve- ja toteutusmallikuvaus
- kuormakuvaus ja palvelutasorajat
- kapasiteetti- ja IT-tehoprofiili
- sijaintiselvitys ja liityntäehdot
- uusiutuvan energian hankintamalli
- hukkalämmön rajapinta ja alustava liiketoimintamalli
- jäähdytysstrategia
- sähköjärjestelmän mitoituksen lähtötiedot
- mittausrajat, mittauspisteet ja KPI-laskentasäännöt.

Näin vihreä datakeskus etenee tarpeesta mitoitukseen ja edelleen toteutukseen ilman, että energianhankinta, hukkalämpö, jäähdytys ja mittaus jäävät irrallisiksi lisäosiksi.

Etenemisjärjestys: tarpeesta suunnitteludokumentteihin

### P1.10 Jos tätä etenemisjärjestystä ei noudateta

**Datakeskuksesta tulee helposti kalliimpi, raskaampi ja vähemmän ympäristökestävä kuin sen olisi tarpeen olla** Kun tarvetta, kuormaa ja tyyppiä ei määritellä ensin, sähkö- ja jäähdytysjärjestelmät mitoitetaan väärien oletusten pohjalta. DOE korostaa, että IT-ratkaisut ja niiden käyttöolosuhteet on arvioitava ensin juuri siksi, että ne määräävät mekaanisten ja sähköisten järjestelmien energiantarpeen. Schneiderin analyysin mukaan vaiheittainen, kuormaan sidottu toteutus voi pienentää TCO:ta noin 30 prosenttia verrattuna ylikapasiteettia sisältävään malliin. ([The Department of Energy's Energy.gov][1])

**Jos sijainti päätetään liian aikaisin, voidaan valita väärä paikka.** Tällöin seurauksena voi olla heikko sähköliittymä, pitkät liityntäajat, kallis sähkö, huono skaalautuvuus tai liian rajalliset mahdollisuudet uusiutuvan energian käyttöön. CBRE Finlandin mukaan sähkötehon saatavuus ja verkon ruuhkautuminen ovat tällä hetkellä keskeisiä datakeskusten kasvun esteitä Euroopassa. ([cbre.fi][2])

**Jos hukkalämpöä ei oteta mukaan heti, sen arvo menetetään.** Tällöin datakeskus jää pelkäksi sähkönkuluttajaksi, vaikka siitä voisi tulla osa paikallista energiajärjestelmää. IEA:n mukaan datakeskusten hukkalämmöllä on merkittävä potentiaali erityisesti rakennuksissa noin viiden kilometrin säteellä, mutta hyödyntäminen edellyttää varhaisia päätöksiä liiketoimintamallista ja tariffirakenteesta. ([IEA][3])

**Jos uusiutuvan energian hankintamalli jätetään myöhemmäksi, vihreys jää helposti pelkäksi väitteeksi ilman luotettavaa todentamista.** GHG Protocol edellyttää, että sähkön hankintaa koskevat instrumentit täyttävät laatukriteerit ja että raportointi on läpinäkyvää. Muussa tapauksessa datakeskus voi kyllä käyttää sähköä tehokkaasti, mutta sen päästöväitteet jäävät heikoiksi tai epäselviksi. ([ghgprotocol.org][4])

**Jos free cooling arvioidaan vasta myöhäisessä vaiheessa, säästöpotentiaali menetetään.** ENERGY STARin mukaan air-side- ja water-side-economizer-ratkaisut voivat säästää erittäin paljon energiaa, koska ne vähentävät mekaanisen jäähdytyksen tarvetta tai ohittavat sen kokonaan. Water-side-economizer voi laskea jäähdytetyn veden tuotantokustannusta jopa 70 prosenttia, ja air-side-ratkaisuilla on raportoitu erittäin suuria energiakustannussäästöjä. Jos tämä havaitaan vasta myöhään, rakennus, putkitus ja laitesijoittelu voivat jo lukita hankkeen raskaampaan jäähdytysratkaisuun. ([ENERGY STAR][5])

**Jos mitoitus tehdään liian aikaisin, seurauksena on joko ylikapasiteettia tai käyttövarmuusriski.** Uptime Instituten mukaan sähkö on edelleen yksi merkittävien datakeskuskatkojen yleisistä juurisyistä. Kun kuormaa, jäähdytystä, varmistusta ja kasvua ei ole määritelty riittävän tarkasti ennen mitoitusta, seurauksena on yleensä joko kallis ylimitoitus tai järjestelmä, joka toimii jatkuvasti väärällä käyttöalueella. ([The Department of Energy's Energy.gov][1])

**Jos mittausrajat päätetään vasta lopussa, tunnusluvuista ei saada uskottavia.** The Green Gridin PUE-ohjeiden tarkoituksena on nimenomaan standardoida mittausta ja raportointia. Jos kokonaisenergiaa, IT-energiaa, jäähdytysenergiaa ja mahdollisesti uudelleenkäytettyä lämpöä ei erotella jo suunnitteluvaiheessa, PUE-, ERE-, CUE- ja muut tunnusluvut eivät ole aidosti vertailukelpoisia. ([ghgprotocol.org][6])

Tiivistettynä: **jos tätä järjestystä ei noudateta, lopputuloksena on useimmiten enemmän sähköä kuluttava, heikommin todennettava ja huonommin integroitava datakeskus.** Green ICT -näkökulmasta suurin virhe ei ole yksittäinen tekninen valinta, vaan se, että datakeskusta ei käsitellä alusta alkaen yhtenä palvelu-, energia-, lämpö- ja mittausjärjestelmänä. ([The Department of Energy's Energy.gov][1])

[1]: https://www.energy.gov/femp/articles/best-practices-guide-energy-efficient-data-center-design?utm_source=chatgpt.com "Best Practices Guide for Energy-Efficient Data Center Design | Department of Energy"
[2]: https://www.cbre.fi/insights/articles/key-factors-to-consider-for-effective-data-centre-site-selection?utm_source=chatgpt.com "Business Insights | Key Factors to Consider for Effective Data Centre Site Selection | CBRE Finland"
[3]: https://www.iea.org/commentaries/opportunities-for-district-heating-in-the-changing-energy-landscape?utm_source=chatgpt.com "Opportunities for district heating in the changing energy landscape - Analysis - IEA"
[4]: https://ghgprotocol.org/scope_2_guidance?utm_source=chatgpt.com "Scope 2 Guidance | GHG Protocol"
[5]: https://www.energystar.gov/products/data_center_equipment/16-more-ways-cut-energy-waste-data-center/use-air-side-economizer?utm_source=chatgpt.com "Use an Air-Side Economizer | ENERGY STAR"
[6]: https://ghgprotocol.org/sites/default/files/standards/Scope%202%20Guidance_Final_Sept26.pdf?utm_source=chatgpt.com "GHG Protocol"

