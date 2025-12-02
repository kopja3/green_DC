# Opas vihreän datakeskuksen rakentamiseksi

**Tekijä:** Jarmo Koponen  

## P0 – Johdanto ja kohderyhmät

### P0.1 Oppaan tarkoitus ja rajaus

Tämä opas kattaa ympäristöystävällisen ja energiatehokkaan datakeskuksen suunnittelun ja toteutuksen perusasiat Suomen olosuhteisiin.  

Opas on suunnattu erityisesti seuraaville kohderyhmille:

- **Tietotekniikka- ja tietoliikenneyritykset:** energiatehokkaiden ja ympäristöystävällisten datakeskusten suunnitteluun ja rakentamiseen.
- **Julkishallinnon organisaatiot:** kestävän kehityksen edistämiseen ja ympäristötavoitteiden saavuttamiseen omissa datakeskuksissa.
- **Koulutus- ja tutkimuslaitokset:** energiatehokkaiden datakeskusten toteuttamiseen laskentatehon ja tietojen säilytyksen tarpeisiin.
- **Teollisuusyritykset:** energiakustannusten ja hiilijalanjäljen vähentämiseen omissa datakeskuksissa.
- **Palveluntarjoajat:** kilpailukyvyn vahvistamiseen tarjoamalla ympäristöystävällisiä ja energiatehokkaita datakeskuspalveluita asiakkaille.

### P0.2 Kenelle opas on tarkoitettu

Tämä opas tarjoaa kokonaisvaltaisen lähestymistavan kestävän ja ympäristöystävällisen datakeskuksen suunnitteluun, joka vastaa digitaalisen infrastruktuurin kasvaviin vaatimuksiin samalla minimoiden ympäristövaikutukset. 

### P0.3 Vihreän datakeskuksen kokonaiskuva

Oppaan kuvailema ihanteellinen datakeskus on:

1. **Toimiva ja tehtävänsä täyttävä:** suunniteltu tehokkaasti toteuttamaan sen tarkoituksen.
2. **Ympäristömääräysten mukainen:** täyttää kaikki tarvittavat ympäristövaatimukset.
3. **Uusiutuvan energian hyödyntäjä:** käyttää mahdollisimman paljon uusiutuvia energialähteitä.
4. **Energiatehokas:** toimii mahdollisimman vähäisellä sähkönkulutuksella.
5. **Hukkalämmön minimointiin tähtäävä:** tuottaa mahdollisimman vähän hukkalämpöä, joka ohjataan korvaamaan hiilidioksidipäästöjä aiheuttavaa energiantuotantoa.
6. **Rajoitetusti ympäristöä lämmittävä:** lämmittää ympäristöään vain minimimäärän.
7. **Helposti huollettava:** suunniteltu helpottamaan tehokasta ylläpitoa.
8. **Vähäisin rakennustöin laajennettava:** mahdollistaa laajentamisen vähäisillä lisärakennustöillä.
9. **Kierrätettävistä materiaaleista valmistettu:** valmistettu pääosin kierrätettävistä ja kestävistä materiaaleista.

Nämä periaatteet ohjaavat oppaan jokaista lukua, tarjoten mallin datakeskuksille, jotka tukevat sekä toiminnallista tehokkuutta että ympäristön kestävyyttä.

Vihreän datakeskuksen suunnittelussa korostetaan energiatehokkuutta, ympäristöystävällisyyttä ja modulaarisuutta, joka mahdollistaa joustavan skaalautuvuuden ja tukee kestäviä liiketoimintakäytäntöjä noudattaen alan ympäristöstandardeja, kuten EU:n energiatehokkuusdirektiiviä.

### P0.4 Yhteys itseopiskelijan oppaaseen (M1–M6)

_Tähän kohtaan voit myöhemmin lisätä taulukon tai listan, joka kertoo, miten perusoppaan luvut vastaavat M1–M6-moduuleja._

### P0.5 Yhteys optimointioppaaseen ja optimointikartoitukseen (O1–O6, Q)

_Tässä kohdassa voit kuvata lyhyesti, miten tämä perusopas linkittyy erilliseen optimointioppaaseen ja sen vaiheisiin (O1–O6, Q)._

---

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


---

# P2 – Miksi datakeskus rakennetaan ja miten sijainti valitaan

Tavoite: perustella, miksi datakeskus rakennetaan omaan käyttöön ja miten sijainti valitaan.

## P2.1 Tehtävä, kapasiteetti ja käyttötarkoitus

Datakeskuksen suunnittelun perustana on selkeä käsitys sen täyttämästä yhteiskunnallisesta tai liiketoiminnallisesta tarpeesta. On määriteltävä, ratkaiseeko keskus esimerkiksi kasvavaa tekoälymallien laskentatehon kysyntää, jolloin tarvitaan korkean suorituskyvyn palvelimia, vai palveleeko se tiettyä sovellusta, kuten verkkosivustojen tai mobiilisovellusten käyttäjäkysyntää, jolloin painopiste on palvelupyyntöjen käsittelyn optimoinnissa. Pilvipohjaista tallennuspalvelua tukevassa datakeskuksessa painotetaan tallennuskapasiteettia ja datan hallintaa.

Käyttötarkoituksen määrittelyn pohjalta arvioidaan tarvittava laitekapasiteetti – palvelinmäärät, laitekaapit ja tallennusratkaisut – sekä sähkönkulutus. Näiden perusteella voidaan mitoittaa myös jäähdytysratkaisut, sähkönsyöttö ja tilatarpeet.

### Oma datakeskus, kolmannen osapuolen konesali vai pilvipalvelut

Ennen rakennuspäätöstä on arvioitava, onko tarkoituksenmukaista:

- **Rakentaa oma datakeskus**, kun tarvitaan pitkäjänteistä kapasiteettia, erityistä tietoturvaa, räätälöityjä ratkaisuja tai integraatiota muuhun fyysiseen infrastruktuuriin (esim. tehdasympäristö, kampus).
- **Hyödyntää kolmannen osapuolen konesalia**, kun rakennus- ja ylläpitoinvestointeja halutaan pienentää, mutta laitteistosta ja alustasta halutaan säilyttää merkittävä oma kontrolli.
- **Tukeutua pilvipalveluihin**, kun kapasiteetin joustavuus, nopea skaalautuvuus ja globaali saavutettavuus ovat keskeisiä tavoitteita.

Usein ratkaisu on näiden yhdistelmä: osa kriittisistä toiminnoista sijoitetaan omaan tai kumppanin datakeskukseen, kun taas osa palveluista tuotetaan julkisen pilven alustoilla.

## P2.2 Sijainnin tekniset tekijät – sähkö, verkko, ilmasto ja vesihuolto

Datakeskuksen sijainnin valinnassa huomioidaan ympäristömääräykset, lainsäädäntö, energian saatavuus sekä paikallisten, uusiutuvien energialähteiden hyödyntämismahdollisuudet. Luotettava ja riittävän vahva sähkönsyöttö on edellytys datakeskuksen toiminnalle. Sijainnin tulee mahdollistaa liityntä kantaverkkoon tai muuhun kapasiteetiltaan riittävään sähköverkkoon, jossa on huomioitu varasyötöt ja mahdolliset tulevat tehotarpeen kasvut.

Myös **verkkoyhteydet** ovat keskeinen tekijä. Datakeskuksen tulee sijaita lähellä riittävän suorituskykyisiä kuituyhteyksiä, jotta viive (latenssi) palveluiden ja käyttäjien välillä pysyy hyväksyttävällä tasolla. Tarvittavien operaattorien ja runkoyhteyksien määrä vaikuttaa sekä luotettavuuteen että kustannuksiin.

**Ilmasto** vaikuttaa jäähdytysratkaisuihin. Sijainti, jossa ulkolämpötila pysyy suuren osan vuodesta matalana, voi mahdollistaa energiansäästöä vapaajäähdytyksellä. Vastaavasti kuumassa ilmastossa tarvitaan tehokkaampia, energiaintensiivisempiä jäähdytysratkaisuja.

Lisäksi on arvioitava **vesihuollon ja jäähdytykseen tarvittavan veden saatavuus**. Jos jäähdytysjärjestelmä perustuu vedenkulutukseen, paikallisen vesivarannon riittävyys ja kestävyys ovat olennainen osa sijaintipäätöstä.

## P2.3 Sijainnin ympäristö- ja energiatehokkuustekijät

Datakeskuksen sijainti vaikuttaa suoraan sekä energiankulutukseen että mahdollisuuksiin hyödyntää uusiutuvaa energiaa ja hukkalämpöä. Jo päätösvaiheessa on tärkeää arvioida:

- **Uusiutuvan energian saatavuus:** voiko datakeskus hyödyntää paikallista tuuli-, aurinko- tai vesivoimaa, tai esimerkiksi biolämpölaitoksia?
- **Hukkalämmön hyödyntäminen:** voiko datakeskus liittää jäähdytysjärjestelmänsä kaukolämpöverkkoon tai muuhun lämpöä tarvitsevaan kohteeseen (esim. asuin- tai toimistorakennukset, kasvihuoneet, uimahallit)?
- **Jäähdytyksen tarve ja ilmasto:** miten paikalliset sääolosuhteet vaikuttavat jäähdytysenergian määrään?

Yksinkertaisia esimerkkiskenaarioita:

- Datakeskus sijaitsee **kaukolämpöverkon vieressä**, jolloin hukkalämpö voidaan ohjata suoraan lämpöverkkoon ja korvata fossiilista lämmöntuotantoa.
- Datakeskus sijaitsee alueella, jossa **ei ole lainkaan lämpöverkkoa**, jolloin hukkalämpö jää hyödyntämättä, ellei erillisiä lämpöä käyttäviä kohteita rakenneta.

Sijaintipäätöksessä kannattaa lisäksi huomioida paikalliset **vesivarat** ja mahdollisuudet toteuttaa jäähdytysratkaisuja, jotka minimoivat sekä energiankulutuksen että vesijalanjäljen.

*Jatkossa tähän alalukuun voidaan kerätä kaikki sijaintiin liittyvät uusiutuva energia / hukkalämpö / vesihuolto -kohdat, jotka muualla tekstissä käsitellään tarkemmin.*

## P2.4 Riskit, resilienssi ja regulaatio sijaintipäätöksissä

Sijaintipäätökseen liittyy aina myös riskejä, jotka on tunnistettava ja arvioitava. Näitä ovat esimerkiksi:

- **Sähkökatkot ja verkon häiriöt**
- **Tulvat ja muut luonnonriskit** (myrskyt, helleaallot, routa)
- **Tulipalot ja paikalliset turvallisuusriskit**
- **Kaapeliviat ja laajakaistayhteyksien katkeaminen**
- **Kyberuhat ja fyysisen turvallisuuden uhkat**
- **Poliittiset ja taloudelliset riskit**, jotka voivat vaikuttaa energia- tai verkkoyhteyksien saatavuuteen ja hintaan

Riskienhallinnan näkökulmasta on tärkeää ymmärtää käsitteet:

- **Varmistus (redundanssi):** kriittisillä komponenteilla, kuten sähkönsyötöllä, jäähdytyksellä ja verkkoyhteyksillä, on varalaitteet ja -reittit.
- **Varayhteys:** toinen, fyysisesti erillinen tiedonsiirtoreitti, jota voidaan käyttää ensisijaisen yhteyden häiriötilanteissa.
- **Varakonesali:** erillinen datakeskus tai laitetila, johon kriittiset palvelut voidaan siirtää tai jossa ne toimivat rinnakkaisena varajärjestelmänä.

Lisäksi sijaintipäätöksissä on huomioitava **regulaatio ja luvitus**: kaavamääräykset, ympäristöluvat, rakennusluvat, mahdolliset melu- ja päästörajat sekä datan sijaintiin liittyvät tietosuojavaatimukset.

*Myöhemmistä luvuista löytyvät riskitekstit ja sääntelymaininnat voidaan koota tiiviiksi yhteenvedoksi tähän alalukuun.*

## P2.5 Tavoitetason ja mittareiden määrittely

Datakeskuksen suunnittelun alkuvaiheessa on hyvä määritellä selkeä **tavoitetaso energiatehokkuudelle ja ympäristövaikutuksille** sekä niitä kuvaavat mittarit. Datakeskusten energiatehokkuutta mitataan kansainvälisesti useilla tunnusluvuilla. EN 50600-4 -standardiperhe kuvaa keskeisiä mittareita, kuten:

- **PUE (Power Usage Effectiveness):** kertoo, kuinka suuri osa datakeskuksen kokonaisenergiankulutuksesta päätyy IT-laitteille.
- **CUE (Carbon Usage Effectiveness):** kuvaa hiilidioksidipäästöjä suhteessa IT-energiankulutukseen.
- **WUE (Water Usage Effectiveness):** kuvaa vedenkulutusta suhteessa IT-energiankulutukseen.
- **Muut ympäristömittarit**, kuten uusiutuvan energian osuus sähkönhankinnassa.

Jo tässä vaiheessa voidaan käyttää yksinkertaista **PUE-esimerkkilaskelmaa**, jossa havainnollistetaan ideatasolla, mitä mittari tarkoittaa (esimerkiksi: jos datakeskus kuluttaa kokonaisuudessaan 1,5 MW ja IT-laitteet 1,0 MW, PUE = 1,5). Tarkemmat laskentamenetelmät ja mittarien määrittelyt käsitellään myöhemmin oppaan EN 50600-4 -standardeja ja mittareita käsittelevässä luvussa.

---

# P3 – Vihreän datakeskuksen elementit ja perusperiaatteet (kestävä suunnittelu)

Tavoite: kuvata, mitä kaikkea vihreässä datakeskuksessa on (rakennus, sähkö, jäähdytys, hukkalämpö, uusiutuva energia, automaatio, materiaalit) ja miten nämä suunnitellaan kestävän kehityksen periaatteiden mukaisesti.

## P3.1 Mitä tarkoitetaan vihreällä datakeskuksella

Vihreä datakeskus on suunniteltu siten, että se kuluttaa mahdollisimman vähän energiaa ja aiheuttaa mahdollisimman pieniä ympäristövaikutuksia. Tämän saavuttamiseksi hyödynnetään uusiutuvia energialähteitä, kuten aurinko- ja tuulivoimaa, sekä optimoidaan energiankäyttöä ja jäähdytystä. Hukkalämmön talteenotolla keskuksen palvelimissa muodostuva lämpöenergiaa voidaan käyttää esimerkiksi kaukolämpöverkossa lähialueen rakennusten lämmitykseen, millä voidaan vähentää hiilidioksidipäästöjä tuottavan energiantuotantomuodon käyttöä. 

Vihreä datakeskus vähentää hiilidioksidipäästöjä ja optimoi energiankäyttöään hyödyntämällä tehokkaita laitteisto- ja ohjelmistoratkaisuja, kuten kuormanhallintaa ja sähkönsyötön tarkkaa ohjausta. Älykkäät algoritmit ja data-analytiikka tukevat energiankulutuksen seurantaa ja optimointia, mikä parantaa energiatehokkuutta kokonaisvaltaisesti.

Modulaarinen suunnittelu mahdollistaa datakeskuksen joustavan laajentamisen tai supistamisen tarpeen mukaan sekä kierrätettävien komponenttien käytön, mikä tukee kestävyystavoitteita ja vastuullista liiketoimintaa. Tavoitteena on täyttää alan ympäristöstandardit ja sääntelyvaatimukset, kuten EU:n energiatehokkuusdirektiivi.

Oppaassa käsitellään vihreän datakeskuksen keskeisiä periaatteita ja tavoitteita, jotka tukevat ympäristöystävällistä ja kestävää IT-infrastruktuuria. Painopiste on sijainnin valinnassa ja infrastruktuurin kestävyydessä energiatehokkuuden, paikallisten resurssien hyödyntämisen ja elinkaaren optimoinnin näkökulmasta. Lisäksi oppaassa käsitellään ympäristösertifikaattien ja standardien täyttämisen merkitystä sekä keskeisiä käytäntöjä ympäristövaikutusten vähentämiseksi. Näitä käytäntöjä ovat muun muassa energianhallinta, hukkalämmön hyödyntäminen sekä materiaalien kierrätys.

## P3.2 Rakennus- ja tilaratkaisut – yksikerroksinen, monikerroksinen ja konttidatakeskus

Suomessa datakeskusten suunnittelussa yleistyy kansainvälisesti käytetty DBO (design–build–operate) -malli, johtuen alan merkittävästä kansainvälisyydestä ja globaalista integraatiosta [lvm 1]. Perussuunnitteluvaiheessa tehdyt päätökset, kuten sijainnin valinta, vaikuttavat datakeskuksen ympäristöystävällisyyteen ja energiatehokkuuteen sen koko elinkaaren ajan. Suunnittelun, rakentamisen ja operoinnin fragmentoituneisuus tuo kuitenkin riskejä ja kustannuspaineita erityisesti energiatehokkuuden ja kustannusten hallinnan näkökulmasta [lvm 1].

**Rakenteelliset ratkaisut**

Datakeskusrakennus suunnitellaan datakeskukselle määritellyn tehtävän perusteella laskettavien laitekaappien ja palvelinkonfiguraatioiden ja lukumäärien perusteella. Eri kerroslukumäärien ja konttidatakeskusten ominaisuuksia arvioidaan tehtävään sopivuuden perusteella:

- **Yksikerroksinen rakenne** helpottaa laitteiden asennusta, huoltoa ja jäähdytysjärjestelmien toteutusta, vähentäen samalla rakenteellisia kuormituksia.
- **Kaksikerroksinen rakenne:** sähkö- ja jäähdytysjärjestelmät sijoitetaan alakertaan ja tietotekniikkalaitteet yläkertaan, jossa jäähdytyksen haihdutustornit ja UPS-järjestelmä [Sharma 1].
- **Konttidatakeskukset** ovat tilankäytöllisesti joustavia ja kustannustehokkaita: ne voidaan helposti sijoittaa lähes mihin tahansa, ja niiden rajoitettu sisätilavuus vähentää ilmankiertohäviöitä ja parantaa hyötysuhdetta jopa 80 % perinteisiin kohotetun lattian keskuksiin verrattuna.

## P3.3 Sähkö- ja energiajärjestelmän periaatteet

Datakeskus liitetään ympäröivään infrastruktuuriin sen sähkönkulutuksen ja palvelupyyntöjen määrän mukaan mitoitetuilla sähkönsyöttö- ja tietoliikenneyhteyksillä, mikä vaikuttaa suunnitteluratkaisuihin. Suomen datakeskukset hyödyntävät Fingrid:in kantaverkosta saatavaa sähköä, jonka siirrosta ja sähköverkon tasapainosta Fingrid vastaa. Kunkin datakeskuksen tarvitsema sähköteho lasketaan tarkasti esisuunnitteluvaiheessa, jossa arvioidaan myös uusiutuvien energialähteiden, kuten tuuli-, aurinko- tai vesivoiman, kannattavuus. Mikäli uusiutuvien energianlähteiden käyttö todetaan kannattavaksi, tehdään tarvittavat tilavaraukset niiden integrointia varten.

EU:n päästöleikkausten ja kiristyvien ympäristövaatimusten ennustetaan merkittävästi vaikuttavan uusiutuvan energian saatavuuteen ja kustannustehokkuuteen vuoteen 2030 mennessä, mikä korostaa esisuunnitteluvaiheen huolellisuutta. Datakeskusten sähkönsyöttö on kriittinen infrastruktuurin jatkuvan toiminnan takaamiseksi, sillä ne toimivat ympäri vuorokauden. Jatkuva sähköenergian saatavuus on elintärkeää, sillä suuri määrä palvelimia, jäähdytysjärjestelmiä ja muita oheislaitteita vaatii huomattavan sähkötehon. Tämä edellyttää tarkkaan suunniteltuja liitäntöjä ja sopimuksia paikallisten verkkoyhtiöiden kanssa, jotka määrittävät tarvittavat tekniset ratkaisut ja varmistavat sähkönsyötön luotettavuuden.     

**Varavoima ja energian varastointi**

Datakeskuksissa on varavoimajärjestelmiä, kuten dieselgeneraattoreita, jotka aktivoituvat sähkökatkon sattuessa. Jatkuvan sähkönsyötön varmistamiseksi akut ja muut energian varastointitekniikat, kuten pumppuvoimalaitokset ja lämpövarastot, ovat keinoja varmistaa, että energiaa on saatavilla myös silloin, kun esimerkiksi aurinko ei paista tai tuuli ei puhalla [13]. Generaattorit ja UPS-järjestelmät sijoitetaan suojattuihin tiloihin kriittisten järjestelmien jatkuvan toiminnan turvaamiseksi.

Sähkönjakelussa kaapelointireitit suunnitellaan lyhyiksi ja selkeiksi ottaen huomioon kunkin rakenneratkaisun erityispiirteet. Tämä vähentää energiahäviöitä ja parantaa sähkönjakelun tehokkuutta sekä ylläpidettävyyttä.

## P3.4 Jäähdytysratkaisut ja ilmankierto

Jäähdytysratkaisut ovat keskeinen osa datakeskuksen energiatehokkuutta. Vihreässä datakeskuksessa hyödynnetään ratkaisuja, jotka minimoivat jäähdytyksen energiankulutuksen ja ympäristövaikutukset.

- **Vapaajäähdytys** hyödyntää ulkoilmaa jäähdytyksessä. Kun ulkolämpötila on riittävän matala, vapaajäähdytys vähentää merkittävästi energiaa kuluttavien jäähdytysjärjestelmien käyttöä ja siten energiankulutusta.
- **Nestejäähdytys** voi kohdistua suoraan prosessoreihin, mikä poistaa tehokkaasti lämpöä laitteista ja vähentää ilmavirran tarvetta [14].

**Ilmankierron optimointi**

Hot aisle– ja cold aisle -konfiguraatiot ovat keskeisiä ilmankierron hallinnassa. Palvelinsalin ilmankierto suunnitellaan erottamalla kuuma ja kylmä ilmavirta toisistaan. Menetelmä vähentää jäähdytysjärjestelmän energiankulutusta jäähdytystehon pysyessä tasaisena. Palvelinsalin kuuma ja kylmäkäytävien ilmankierto suunnitellaan tiiviiksi, jotta lämpöä ei pääse siirtymään kuumasta ilmasta kylmään virtaan.	

Jäähdytysjärjestelmän suunnittelussa huomioidaan palvelimien ja muiden IT-laitteiden tuottama lämpöteho, datakeskuksen koko ja sijainnin ympäristöolosuhteet. Järjestelmä mitoitetaan poistamaan hukkalämpö mahdollisimman tehokkaasti ja tasaisesti koko datakeskuksesta.

**Rakenteelliset ratkaisut ja ilmasto**

Yksikerroksisessa datakeskuksessa laitteiden sijoittelu tukee ilmankiertoa ja helpottaa jäähdytyksen hallintaa. Kaksikerroksisessa rakenteessa laitekaapit sijoitetaan yläkertaan, jolloin vapaajäähdytystä voidaan hyödyntää suoraan yläkerroksen katon kautta. Lämmin ilma nousee luonnollisesti ylös, mistä se voidaan tehokkaasti poistaa ilmanvaihtojärjestelmän tai haihdutustornien avulla. Tämä vähentää mekaanisen jäähdytyksen tarvetta ja pienentää energiankäyttöä. Lisäksi yläkerroksen rakenne mahdollistaa suoraviivaisen ilmavirran hallinnan, mikä tukee tehokasta jäähdytystä ja vähentää lämpöhukkaa.

Sijainti ja ulkolämpötilan vaihtelut vaikuttavat jäähdytyksen tarpeeseen. Pohjoisilla alueilla voidaan hyödyntää kylmää ulkoilmaa jäähdytykseen merkittävästi enemmän kuin lämpimämmillä alueilla. Jäähdytysjärjestelmät suunnitellaan helposti huollettaviksi ja modulaarisiksi, jotta niiden komponentit voidaan vaihtaa tai päivittää häiritsemättä datakeskuksen toimintaa. Jäähdytysjärjestelmissä on käytettävä korkean hyötysuhteen laitteita, jotka on optimoitu datakeskuksen erityistarpeisiin.

## P3.5 Hukkalämmön talteenotto ja hyödyntäminen

Hukkalämmön hyödyntämisen mahdollisuus ja kannattavuus arvioidaan jo esisuunnitteluvaiheessa. Mikäli hukkalämpö hyödynnetään kaukolämpöverkossa, datakeskuksen rakennussuunnittelussa huomioidaan tarvittavat lämmönvaihtimet ja muut infrastruktuuriratkaisut. Palvelimien tuottama hukkalämpö voidaan tehokkaasti ohjata kaukolämpöverkkoon tai käyttää läheisten rakennusten lämmitykseen, mikä vähentää fossiilisten polttoaineiden käyttöä ja pienentää hiilidioksidipäästöjä. Lämmönvaihtimet siirtävät hukkalämmön kaukolämpöverkkoon, ja lämpöpumput nostavat tarvittaessa sen lämpötilaa lämmitystarpeisiin sopivaksi.

Hukkalämmön hyödyntäminen parantaa datakeskuksen energiatehokkuutta ja pienentää sen ympäristövaikutuksia merkittävästi [Fortum 1]. Mikäli hukkalämmön hyödyntäminen ei ole mahdollista, lämpö johdetaan ympäristönormien mukaisesti esimerkiksi mereen tai ilmakehään haittavaikutusten minimoimiseksi. Esimerkiksi Pariisin alueella datakeskusten hukkalämpöä hyödynnetään jo laajasti kaukolämpöverkossa, mikä vähentää rakennusten energiakustannuksia ja hiilidioksidipäästöjä [15]. Hukkalämmön talteenotto on yksi tehokkaimmista tavoista vähentää datakeskusten ympäristövaikutuksia ja integroida ne osaksi vastuullista ja resurssitehokasta energiainfrastruktuuria.

## P3.6 Uusiutuvan energian integraatio

Paikallinen uusiutuva energia on tärkeä osa vihreän datakeskuksen energiastrategiaa. Suunnittelussa:

- varataan tilaa **aurinkopaneeleille** tai **tuulivoimalle**, jotta voidaan vähentää riippuvuutta fossiilisista polttoaineista
- tehdään **yhteistyösopimuksia (PPA)** uusiutuvan energian toimittajien kanssa, jos omaa tuotantoa ei voida toteuttaa riittävästi.

Uusiutuvien energialähteiden, kuten aurinko- ja tuulivoiman, integrointi datakeskuksiin on keskeistä hiilidioksidipäästöjen vähentämiseksi ja ympäristöystävällisen toiminnan tukemiseksi.

Tietoliikenneyhteydet mitoitetaan tehtävään määriteltyjen palvelupyyntöjen mukaan riittäviksi ja luotettaviksi. Tämä edellyttää yhteistyötä teleoperaattoreiden kanssa.

**Vesihuolto**

Datakeskuksen suunnitteluvaiheessa on varmistettava ja suunniteltava riittävä veden saanti jäähdytysjärjestelmille sekä asianmukainen jätevedenkäsittely.

## P3.7 Automaatio, mittaus ja reaaliaikaiset valvontajärjestelmät

Vihreissä datakeskuksissa seurataan ja optimoidaan jatkuvasti energiankulutusta ja resurssien käyttöä. Automaation, tekoälyn ja data-analytiikan avulla voidaan ohjata järjestelmiä reaaliaikaisesti ja vähentää energiankulutuksesta aiheutuvia päästöjä [17].

**Reaaliaikaiset valvontajärjestelmät**

- **Energiaseuranta:** käytetään energianseurantajärjestelmiä, jotka mittaavat PUE-arvoa ja muita tärkeitä suorituskykymittareita.
- **Kuormituksen hallinta tekoälyllä:** hyödynnetään syväoppimista ja koneoppimista resurssien dynaamiseen kohdentamiseen kysynnän mukaan.
- **Ympäristöolosuhteiden seuranta:** seurataan lämpötilaa, ilmankosteutta ja ilmankiertoa automaatiolla energiatehokkuuden ylläpitämiseksi.

Tekoälyn ja data-analytiikan käyttö datakeskusten energiankulutuksen ja hiilijalanjäljen mittaamisessa on keskeinen osa datakeskusten ympäristöystävällisyyden parantamista. Tekoäly voi optimoida energiankäyttöä, seurata kulutusta reaaliajassa ja auttaa vähentämään energiankulutuksesta aiheutuvia päästöjä [18]. 

**Tekoälyn rooli energiankulutuksen vähentämisessä**

Google DeepMindin tekoälyä hyödyntävä järjestelmä onnistui vähentämään Googlen datakeskusten jäähdytyksen energiankulutusta jopa 40 %. Tämä saavutettiin optimoimalla jäähdytysjärjestelmän toiminta reaaliaikaisten tietojen avulla. Tämä johti myös 15 % vähennykseen datakeskusten yleisessä energiankulutuksessa, mikä on merkittävä parannus ympäristövaikutusten vähentämisessä [18]. 

**Data-analytiikan merkitys**

Data-analytiikka voi tukea jatkuvaa hiilijalanjäljen mittaamista. Esimerkiksi Microsoftin Emissions Impact Dashboard tarjoaa työkalut pilviympäristön hiilijalanjäljen laskentaan, mikä auttaa organisaatioita seuraamaan ja optimoimaan energiankäyttöään sekä vähentämään päästöjä koko toimitusketjussa [19].

Yhdistämällä tekoälyn kyvyn analysoida valtavia tietomääriä ja optimoida energiankulutus tehokkaasti datakeskukset voivat merkittävästi pienentää ympäristövaikutuksiaan ja saavuttaa parempaa energiatehokkuutta.

Automaattinen datankeruu on olennainen osa tätä kokonaisuutta. Datakeskuksen tehokkuuden ja ympäristöystävällisyyden kehittämiseksi on tärkeää automatisoida keskeisten mittapisteiden tiedonkeruu. Tähän sisältyy datakeskuksen jäähdytysjärjestelmän sähkönkulutuksen, hukkalämmön määrän (jos talteenotto on käytössä), sekä datakeskuksen ja palvelimien lämpötilojen jatkuva seuranta. Lisäksi mitataan datakeskuksen, palvelimien ja jäähdytysjärjestelmän sähkönkulutus, palvelimien käyttöaste ja kuormitus sekä uusiutuvan energian osuudet datakeskuksen energiankäytössä (Kuva x). 

<p>
  <img src="./img/p3-kuva3-datakeskuksen-mittaus-jarjestelma.png"
       alt="Kuva x. Datakeskuksen automaattinen mittaus- ja seurantajärjestelmä energiatehokkuuden ja ympäristövaikutusten optimointia varten."
       style="width:100%;height:auto;">
</p>

*Kuva x. Datakeskuksen automaattinen mittaus- ja seurantajärjestelmä energiatehokkuuden ja ympäristövaikutusten optimointia varten.*

Tämä automaattinen datankeruu mahdollistaa PUE (Power Usage Effectiveness), REF (Renewable Energy Factor), ERF (Energy Reuse Factor) ja WUE (Water Usage Effectiveness) -arvojen laskentaan tarvittavien ominaisuuksien keräämisen. Se tukee myös syväoppivien ja koneoppimista hyödyntävien järjestelmien käyttöä, joiden avulla voidaan ennakoida energiantarvetta ja optimoida järjestelmien tehokkuutta. Näin datankeruu edistää merkittävästi datakeskuksen ympäristöystävällisyyden parantamista pitkällä aikavälillä.

## P3.8 Kestävät materiaalivalinnat ja kiertotalous

Kestävässä datakeskusten suunnittelussa korostuvat modulaarisuus, pitkä käyttöikä ja kierrätettävyys. Modulaarinen arkkitehtuuri mahdollistaa datakeskusten asteittaisen laajentamisen ilman tarpeettoman suuren kapasiteetin rakentamista alusta alkaen. Tämä tarkoittaa, että keskuksen infrastruktuuria voidaan laajentaa vähitellen vastaamaan kysynnän kasvua, mikä vähentää rakennusmateriaalien ja energian hukkaa sekä tarjoaa paremman resurssien hallinnan [20]. 

Modulaariset datakeskukset hyödyntävät myös energiatehokkaita teknologioita, kuten vesijäähdytystä ja uusia laitteistoratkaisuja, jotka minimoivat energiankulutusta. Tämä vähentää hiilijalanjälkeä ja pidentää laitteiston käyttöikää, mikä on keskeistä kierrätettävyystavoitteiden saavuttamisessa. Modulaariset järjestelmät ovat usein esivalmistettuja ja testattuja tehtaalla, mikä vähentää rakennusvaiheen jätettä ja lisää luotettavuutta [20]. 

Lisäksi pitkäikäisyyttä ja kierrätettävyyttä edistävät kestävämmät materiaalit, kuten teräksen käyttö, joka on helpommin kierrätettävissä kuin betoni. Tämä lähestymistapa auttaa minimoimaan ympäristövaikutuksia koko datakeskuksen elinkaaren ajan [20]. Kestävään datakeskussuunnitteluun kuuluvat modulaarisuus, pitkä käyttöikä ja kierrätettävyys. Kestävät materiaalit, kuten kierrätettävä teräs, tukevat hiilijalanjäljen vähentämistä ja pidentävät infrastruktuurin käyttöikää, mikä auttaa minimoimaan ympäristövaikutuksia koko elinkaaren ajan [20]. 

Vihreissä konesaleissa suositaan modulaarisia ratkaisuja, jotka mahdollistavat datakeskuksen laajentamisen tai pienentämisen tarpeen mukaan. Kestävä suunnittelu huomioi myös laitteiden pitkä käyttöikä ja kierrätettävyys, mikä vähentää elektroniikkajätteen määrää [19].

Vihreän datakeskuksen tavoitteena on tukea kestäviä ja vastuullisia liiketoimintatapoja, jotka noudattavat ympäristöstandardien ja lainsäädännön vaatimuksia, kuten EU:n energiatehokkuusdirektiivejä korostaen energiatehokkuutta, uusiutuvan energian käyttöä ja hiilijalanjäljen minimointia.

---

# P4 – Datakeskuksen elinkaaren vaiheet

Tavoite: kuvata vihreän datakeskuksen elinkaari esiselvityksestä suunnitteluun, rakentamiseen, käyttöön, modernisointiin ja purkuun. Luku syventää M3-moduulin sisältöä.

## P4.1 Esiselvitys ja tavoitteiden asettaminen

Elinkaaren ensimmäinen vaihe on esiselvitys, jossa määritellään datakeskuksen rooli, tehtävä ja tavoitteet. Tässä vaiheessa arvioidaan:

- mitä liiketoiminnallista tai yhteiskunnallista tarvetta datakeskus palvelee  
- kuinka paljon laskentatehoa, tallennuskapasiteettia ja verkkokapasiteettia tarvitaan  
- mikä on palveluiden tavoiteltu käytettävyystaso (esim. SLA-prosentit).

Vihreän datakeskuksen kannalta esiselvityksessä on tärkeää asettaa myös **ympäristö- ja energiatehokkuustavoitteet**. Näitä voivat olla esimerkiksi:

- tavoiteltu **PUE-taso** (Power Usage Effectiveness)  
- sallitut tai tavoitellut **CO₂-päästöt per palveluyksikkö**  
- uusiutuvan energian osuus sähkönhankinnassa  
- tavoitteet vedenkulutukselle ja hukkalämmön hyödyntämiselle.

Esiselvityksen tuloksena syntyy kokonaiskuva, jonka perusteella voidaan päättää, rakennetaanko oma datakeskus, hyödynnetäänkö kolmannen osapuolen konesalia vai tukeudutaanko pääosin pilvipalveluihin – tai yhdistelmään näistä.

## P4.2 Suunnitteluvaihe

Suunnitteluvaiheessa esiselvityksen tavoitteet muutetaan konkreettisiksi ratkaisuiksi. Tässä vaiheessa:

- valitaan **toimintamalli**, kuten DBO-malli (design–build–operate) tai muu kumppanuusmalli  
- kilpailutetaan ja valitaan **toimittajat** (rakentaminen, sähkönsyöttö, jäähdytys, automaatio, valvonta)  
- päätetään **perusratkaisut** rakennus-, sähkö-, jäähdytys- ja automaatiojärjestelmille.

Suunnittelussa huomioidaan myös:

- **sijaintiin liittyvät edellytykset**: liitynnät sähkö- ja lämpöverkkoihin, tietoliikenneyhteydet, ilmasto ja vesihuolto  
- mahdollisuus **uusiutuvan energian** hyödyntämiseen ja hukkalämmön kytkemiseen esimerkiksi kaukolämpöverkkoon  
- tilavaraukset tuleville teknologioille, kuten uusille jäähdytysratkaisuille tai energian varastointitekniikoille.

### Sääntöjen ja ympäristöstandardien noudattaminen

Vihreän datakeskuksen suunnittelussa on varmistettava, että datakeskus:

- täyttää **paikalliset ja kansalliset ympäristö- ja rakennusmääräykset**  
- noudattaa **tietoturva- ja tietosuojasääntelyä** (esim. datan sijainti ja varmuuskopiointi)  
- voi tavoitella tarvittavia **ympäristösertifikaatteja** (esim. LEED, BREEAM tai muita alan standardeja).

Sertifikaattitavoitteet on hyvä kirjata jo suunnitteluvaiheessa, jotta vaatimukset voidaan huomioida materiaalivalinnoissa, energiainfrastruktuurissa ja rakennuksen toteutuksessa.

## P4.3 Rakentaminen

Rakentamisvaiheessa suunnitelmat muuttuvat konkreettiseksi infrastruktuuriksi. Keskeisiä asioita ovat:

- **maanrakennus ja perustusratkaisut**, joissa huomioidaan kantavuus, routa, mahdolliset tulvariskit ja kaapelireitit  
- **rakennuksen runko ja tilaratkaisut** (yksikerroksinen, monikerroksinen tai konttirakenne)  
- **sähkö- ja jäähdytysjärjestelmien asennus**, mukaan lukien UPS-laitteet, varavoimajärjestelmät, muuntajat ja jäähdytyslaitteet  
- **kaapelointi ja kytkennät** IT-laitteille, automaatiolle ja valvontajärjestelmille.

Kestävän rakentamisen kannalta on tärkeää käyttää mahdollisuuksien mukaan **kierrätettäviä ja vähäpäästöisiä materiaaleja**, minimoida rakennusjätteet sekä suunnitella logistiikka energiatehokkaaksi (esivalmistetut moduulit, lyhyet kuljetusketjut jne.).

## P4.4 Käyttöönotto

Käyttöönotossa varmistetaan, että datakeskus toimii suunnitellulla tavalla ennen tuotantokäyttöä. Tähän sisältyy:

- **järjestelmätestit**: sähkönsyöttö, varavoima, jäähdytys, automaatio, valvonta ja hälytysjärjestelmät  
- **kuormitustestit**: palvelinsalin kuormittaminen suunnitellulle tasolle, jolloin mitataan lämpötilat, jäähdytyksen toimivuus ja energiankulutus  
- **turvallisuustestit**: fyysinen turvallisuus, palo- ja pelastusturvallisuus sekä kyberturvallisuuteen liittyvät perusratkaisut  
- ensimmäinen **PUE- ja muiden tunnuslukujen mittaus**, jotta saadaan vertailupiste jatkuvalle seurannalle.

Käyttöönoton jälkeen datakeskus siirtyy operointivaiheeseen, jossa seuranta- ja mittausjärjestelmiä hyödynnetään päivittäisessä johtamisessa.

## P4.5 Käyttö, operointi ja ylläpito

Käyttövaihe on datakeskuksen pisin vaihe. Sen aikana varmistetaan, että:

- palvelut ovat **käyttäjille saatavilla** sovitun palvelutason mukaisesti  
- **energiankulutusta ja ympäristövaikutuksia seurataan** säännöllisesti (PUE, CO₂-päästöt, hukkalämmön hyödyntäminen, vedenkulutus)  
- **ennakoiva huolto** ja laitteiden kunnonvalvonta ehkäisevät häiriöitä  
- dokumentaatio, varautumissuunnitelmat ja toipumiskäytännöt (DR/BCP) pidetään ajan tasalla.

Vihreässä datakeskuksessa operointi kytkeytyy tiiviisti optimointiin: kuormanhallinta, automaattinen mittaus ja tekoälyyn perustuva ohjaus tukevat jatkuvaa energiatehokkuuden parantamista. Päivittäisessä johtamisessa on hyvä hyödyntää **selkeitä mittaristoja** ja raportointia, joita käsitellään tarkemmin oppaan myöhemmissä mittariluvuissa (P5–P7).

## P4.6 Modernisointi ja kapasiteetin laajennus

Teknologian kehittyminen, palvelupyyntöjen kasvu ja ympäristövaatimusten tiukentuminen johtavat siihen, että datakeskusta on aika ajoin modernisoitava. Modernisointi voi tarkoittaa esimerkiksi:

- vanhojen, paljon energiaa kuluttavien **palvelimien ja jäähdytyslaitteiden korvaamista** energiatehokkaammilla  
- **kapasiteetin laajentamista** lisäämällä laitekaappeja tai laajentamalla rakennusta  
- **uusiutuvan energian osuuden kasvattamista** tai hukkalämmön hyödyntämisen tehostamista  
- automaatio- ja valvontajärjestelmien päivittämistä, jotta reaaliaikainen optimointi on mahdollista.

Suunnitteluvaiheessa tehty **modulaarinen arkkitehtuuri** helpottaa modernisointia: uusia moduuleja voidaan lisätä tai vanhoja poistaa häiritsemättä koko datakeskuksen toimintaa.

## P4.7 Purku ja elinkaaren loppu (kiertotalous)

Elinkaaren viimeisessä vaiheessa datakeskus tai sen osa puretaan. Vihreän datakeskuksen näkökulmasta purku ei ole vain loppu, vaan mahdollisuus kiertotalouteen:

- rakennusmateriaalit (esim. teräs, metallit) pyritään **kierrättämään tai uudelleenkäyttämään**  
- IT-laitteet, kaapelit ja muut komponentit käsitellään **sähkö- ja elektroniikkaromua koskevien säädösten** mukaisesti  
- vaaralliset aineet (esim. tietyt jäähdytysaineet, akut) poistetaan ja käsitellään **turvallisesti ja ympäristöystävällisesti**  
- puretun infrastruktuurin tilalle voidaan suunnitella uutta käyttöä, joka tukee alueen kestävää kehitystä.

Hyvin suunniteltu elinkaari huomioi purkuvaiheen jo alussa: materiaalivalinnoissa suositaan ratkaisuja, jotka ovat helposti eroteltavissa ja kierrätettävissä.

## P4.8 Kestävä ja modulaarinen suunnittelu läpi elinkaaren

Kestävä datakeskus ei synny yksittäisistä ratkaisuista, vaan **kokonaisvaltaisesta elinkaariajattelusta**. Modulaarinen ja kestävä suunnittelu läpäisee kaikki vaiheet:

- **modulaarisuus** mahdollistaa kapasiteetin kasvattamisen vaiheittain ilman ylimitoitettua alkuinvestointia  
- **pitkä käyttöikä** ja laitteiden päivitettävyys pienentävät ympäristövaikutuksia ja elinkaarikustannuksia  
- **kierrätettävyys** ohjaa materiaalivalintoja niin rakennuksessa kuin IT-laitteissakin.

Suunnittelussa kannattaa dokumentoida elinkaaren aikaiset päätökset ja varmistaa, että ne tukevat myöhempiä vaiheita: modernisointia, purkua ja materiaalien kiertoa. Näin datakeskuksen hiilijalanjälki ja ympäristövaikutukset pysyvät hallittavina koko elinkaaren ajan.

## P4.9 Tulevaisuuden varautuminen ja pitkän aikavälin suunnittelu

Tulevaisuuden varautuminen on olennainen osa vihreän datakeskuksen elinkaarisuunnittelua. Huomioitavia asioita ovat:

- **Skaalautuvuus:** datakeskus suunnitellaan laajennettavaksi tai supistettavaksi palvelupyyntöjen määrän mukaan. Tämä voi tarkoittaa modulaarisia rakennusratkaisuja, laajennusvaraa sähkö- ja jäähdytysjärjestelmissä sekä joustavaa palvelinarkkitehtuuria.
- **Teknologian kehittyminen:** varataan tilaa ja resursseja tuleville teknologisille päivityksille, kuten uusille jäähdytysratkaisuille, energian varastointitekniikoille tai uusiutuvan energian tuotantomuodoille.
- **Huollettavuus ja päivitettävyys:** laitteistot suunnitellaan helposti huollettaviksi ja komponentit helposti vaihdettaviksi. Tämä pitää elinkaarikustannukset alhaisina, pidentää laitteiden käyttöikää ja vähentää elektroniikkajätteen määrää.
- **Sääntelyn muutokset:** varaudutaan siihen, että ympäristö- ja energiatehokkuusvaatimukset voivat kiristyä. Joustavat ratkaisut ja selkeä mittaristo helpottavat uusien vaatimusten täyttämistä.

Hyvin suunniteltu vihreä datakeskus ei ole vain tämän päivän tarpeisiin rakennettu konesali, vaan **pitkän aikavälin infrastruktuuri**, joka mukautuu teknologian, sääntelyn ja liiketoiminnan muutoksiin kestävällä tavalla.

---

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

---

# P6 – Energian kulutus ja hukkalämmön hyödyntäminen

Tavoite: syventää M5-moduulin sisältöä ja selittää, mistä datakeskuksen kilowattitunnit syntyvät, miten ne jakautuvat eri komponenttien kesken ja miten tämä näkyy hiilidioksidipäästöissä sekä hukkalämmön hyödyntämisen potentiaalissa.

## P6.1 Energiankulutuksen jakautuminen datakeskuksessa

Datakeskuksessa kulutettu sähköenergia jakautuu useiden komponenttien kesken. Suurimman osan energiasta kuluttavat palvelimet, mutta merkittäviä osuuksia käyttävät myös jäähdytysjärjestelmät, verkkolaitteet ja sähkönsyötön apujärjestelmät (UPS, PDU, muuntajat jne.).

Palvelimet käyttävät yleisesti noin **50–70 %** datakeskuksessa käytettävästä sähköenergiasta, sisältäen prosessorit, muistit ja virtalähteiden häviöt [4]. Loput energiasta jakautuu pääasiassa jäähdytysjärjestelmien, verkkolaitteiden ja UPS-järjestelmien kesken.

### P6.1.1 Prosessorit (CPU)

Prosessorit muodostavat merkittävän osan palvelimen sähkönkulutuksesta. Yksittäinen prosessori kuluttaa työkuormasta riippuen noin **45–200 W**, ja niiden osuus palvelimen kokonaistehonkulutuksesta on tyypillisesti **25–40 %** [5].  

Mitä raskaampia laskentatehtäviä (esim. tekoälymallit, tietokantakyselyt) suoritetaan, sitä suurempi osuus energiasta kohdistuu prosessoreihin.

### P6.1.2 Muisti (RAM)

Muisti kuluttaa tyypillisesti noin **20–30 %** palvelimen sähkötehosta [5]. Kulutukseen vaikuttavat:

- muistikanavien määrä  
- muistimoduulien kapasiteetti  
- työkuormien muistivaatimukset sekä moniydinprosessorien käyttö.

Muistia paljon käyttävät sovellukset (esim. in-memory-tietokannat) voivat kasvattaa merkittävästi palvelimen kokonaisenergiankulutusta.

### P6.1.3 Virtalähteet (PSU)

Virtalähteiden (PSU, Power Supply Unit) osuus palvelimen kokonaisenergiasta on tyypillisesti **10–20 %** [6].  

Virtalähteen hyötysuhdetta parantaa muun muassa **Power Factor Correction (PFC)**, joka vähentää loistehoa ja energiahävikkiä. Hyötysuhteeltaan korkeammat virtalähteet (esim. 80 PLUS -sertifioidut) tukevat parempaa kokonaisenergiatehokkuutta.

### P6.1.4 Verkkolaitteet

Verkkolaitteet, kuten reitittimet ja kytkimet, käyttävät arviolta noin **8 %** datakeskuksen sähköenergiasta, mikä suurissa keskuksissa voi vastata jopa **0,8 MW** tehoa [5].  

Erityisesti runkoverkossa käytettävät korkean kapasiteetin laitteet (10–400 Gbit/s portit) kuluttavat paljon energiaa, minkä vuoksi niiden valinnassa ja konfiguroinnissa kannattaa huomioida energiatehokkuusominaisuudet.

### P6.1.5 Tehonhallinta ja UPS-järjestelmät

Tehonhallintayksiköt ja UPS-järjestelmät kuluttavat yleensä noin **10–12 %** datakeskuksen energiasta [6].  

Vaikka UPS-järjestelmät ovat välttämättömiä sähkönsyötön varmistamiseksi, niiden häviöt kasvattavat kokonaiskulutusta. Siksi:

- UPS-järjestelmät mitoitetaan oikean kokoisiksi  
- hyötysuhteeltaan korkeita ratkaisuja suositaan  
- toimintaa seurataan jatkuvasti mittaustietojen avulla.

## P6.2 Jäähdytyksen energiankulutus ja suhteellinen osuus

Jäähdytysjärjestelmät ovat toinen suuri energiankuluttaja datakeskuksessa. Tyypillisesti:

- **jäähdytysjärjestelmät** (esim. CRAC-yksiköt, pumput, puhaltimet) käyttävät noin **30–40 %** koko datakeskuksen energiasta [4, 5].

Jäähdytyksen energiankulutusta voidaan pienentää esimerkiksi:

- hyödyntämällä **vapaajäähdytystä**, kun ulkolämpötila on riittävän matala  
- käyttämällä **korkean hyötysuhteen** jäähdytyslaitteita  
- optimoimalla **ilmavirtoja** (hot/cold aisle) ja lämpötilan asetusarvoja  
- ottamalla käyttöön **nestejäähdytys** suuritehoisille palvelimille.

Jäähdytyksen suhteellinen osuus näkyy suoraan PUE-luvussa: mitä vähemmän energiaa kuluu jäähdytykseen suhteessa IT-kuormaan, sitä lähempänä PUE-arvo on 1,0.

## P6.3 Energia, kWh ja päästöt (perusfysiikka)

Energia määritellään työn kautta. Energiankansainvälinen SI-yksikkö on **joule (J)**, ja sähköenergian yleinen yksikkö on **kilowattitunti (kWh)**.  

Yksi kilowattitunti vastaa **3,6 megajoulea**. Kilowattitunti lasketaan kertomalla sähkölaitteen teho (kilowatteina, kW) sillä ajalla, jonka laite on ollut käytössä (tunteina, h):

> **kWh = teho (kW) × käyttöaika (h)**

Datakeskuksen tapauksessa:

- jos IT-kuorma on keskimäärin 500 kW ja sitä ajetaan 24 h vuorokaudessa, energiankulutus on  
  500 kW × 24 h = 12 000 kWh / vrk.

Hiilidioksidipäästöjen arvioinnissa käytetään **päästöintensiteettiä**, joka ilmoittaa kuinka paljon CO₂-päästöjä syntyy yhtä kWh:ta kohti (esim. gCO₂/kWh tai kgCO₂/kWh).  

Päästöarvio saadaan:

> **CO₂-päästöt = energian kulutus (kWh) × päästöintensiteetti (kgCO₂/kWh)**

## P6.4 Miksi datakeskus aiheuttaa hiilidioksidipäästöjä

Hiilidioksidipäästöjen määrä riippuu datakeskuksen kuluttamasta sähköenergiasta ja siitä, miten sähkö tuotetaan. Datakeskukset toimivat ympäri vuorokauden ja vaativat jatkuvan energiantuotannon, mikä lisää sähkön kulutusta ja edelleen hiilidioksidipäästöjä, jos energialähteet eivät ole uusiutuvia.

Suuri määrä palvelimia, jäähdytysjärjestelmiä ja muita infrastruktuurilaitteita vaatii jatkuvaa sähköä toimiakseen. Jos sähkö tuotetaan fossiilisilla polttoaineilla, kuten kivihiilellä, maakaasulla tai öljyllä, syntyy merkittävästi hiilidioksidipäästöjä (Kuva 3).

*Kuva 3. Hiilivoimala aiheuttaa merkittäviä hiilidioksidipäästöjä (vasemmalla), kun taas aurinko-, tuuli- ja vesivoimalat tuottavat sähköenergiaa vähäisin päästöin (oikealla).*

Suomen sähköenergiasta tuotetaan ydinvoimalla noin 30 %. Uusiutuvista energialähteistä tuulivoiman osuus kasvaa jatkuvasti, ja sen arvioidaan tuottavan jopa 50 % maan sähköstä vuoteen 2030 mennessä. Myös aurinkoenergiaa käytetään kasvavassa määrin, mutta sen osuus on edelleen verrattain pieni. Fossiiliset polttoaineet ja maakaasu ovat pienentyvä osa Suomen sähköntuotantoa, mutta niitä käytetään edelleen erityisesti kulutushuippujen aikana [2, 3].

Useissa datakeskuksissa on varavoimajärjestelmiä, kuten dieselgeneraattoreita, jotka aktivoituvat sähkökatkon sattuessa. Näiden käyttö aiheuttaa lisäpäästöjä erityisesti huoltokatkosten ja hätätilanteiden aikana. Jatkuvan sähkönsyötön varmistamiseksi tarvitaan energian varastointijärjestelmiä, jotka voivat tasata uusiutuvien energianlähteiden vaihtelevaa saatavuutta. Akut ja muut energian varastointitekniikat, kuten pumppuvoimalaitokset ja lämpövarastot, ovat keinoja varmistaa, että energiaa on saatavilla myös silloin, kun esimerkiksi aurinko ei paista tai tuuli ei puhalla [13].  

Vihreissä datakeskuksissa hyödynnetään mahdollisimman paljon uusiutuvia energialähteitä, kuten aurinkoa, tuulta tai vesivoimaa. Tämä vähentää riippuvuutta fossiilisista polttoaineista ja tukee hiilidioksidipäästöjen vähentämistä [5, 12].

## P6.5 Vihreä datakeskus ja energiatehokkuus

Vihreät datakeskukset suunnitellaan kuluttamaan mahdollisimman vähän energiaa käyttämällä energiatehokkaita laitteisto- ja ohjelmistoratkaisuja. Tähän kuuluvat:

- korkean hyötysuhteen laitteet (palvelimet, UPS-laitteet, pumput, puhaltimet)  
- kuormanhallinta ja sähkönsyötön optimointi  
- älykäs sähkönjakelu ja uusiutuvan energian yhdistäminen energian varastointijärjestelmiin [10].

Vihreä datakeskus edistää IT-infrastruktuurin ja laskentakapasiteetin energiatehokasta ja ympäristöystävällistä hyödyntämistä käyttämällä uusiutuvia energialähteitä ja vähentämällä energiankulutusta. Tämä saavutetaan energiatehokkaiden laitteiden, älykkäiden jäähdytysratkaisujen ja kierrätysmenetelmien avulla sekä noudattamalla kestävän kehityksen periaatteita koko datakeskuksen elinkaaren ajan [4].

Virtuaalisointi on tärkeä osa energiatehokkuutta: fyysisten palvelimien energiatehokkuutta parannetaan, ja yhä enemmän käytetään virtuaalipalvelimia, jotka mahdollistavat useiden työkuormien ajamisen samalla fyysisellä laitteistolla. Tämä vähentää fyysisten palvelimien määrää, säästää energiaa ja tilaa sekä pienentää jäähdytystarvetta [16].

Modulaarinen suunnittelu mahdollistaa datakeskuksen joustavan laajentamisen tai supistamisen ilman tarpeetonta resurssien hukkaa. Kestävä suunnittelu keskittyy pitkäikäisiin, kierrätettäviin laitteisiin ja materiaaleihin, jotka vähentävät elektroniikkajätteen määrää ja tukevat kiertotaloutta.

## P6.6 Hukkalämmön potentiaali ja energiatase

Käytännössä lähes kaikki IT-laitteiden ja sähköjärjestelmien kuluttama energia muuttuu lopulta **lämmöksi**. Hukkalämmön hyödyntäminen on siksi yksi tehokkaimmista tavoista parantaa datakeskuksen energiataseita ja pienentää sen hiilijalanjälkeä.

Hukkalämmön hyödyntämisen mahdollisuus ja kannattavuus arvioidaan jo esisuunnitteluvaiheessa. Mikäli hukkalämpö voidaan kytkeä esimerkiksi kaukolämpöverkkoon, datakeskuksen rakennussuunnittelussa huomioidaan:

- tarvittavat **lämmönvaihtimet**  
- **lämpöpumput** lämpötilan nostamiseksi lämmitykseen sopivaksi  
- liitynnät kaukolämpöverkkoon tai muihin lämpöä tarvitsemiin kohteisiin.

Hyvin suunniteltu järjestelmä voi siirtää merkittävän osan datakeskuksen käyttämästä sähköenergiasta hyötylämmöksi rakennusten tai prosessien lämmitykseen. Tämä:

- pienentää fossiilisilla polttoaineilla tuotetun lämmön tarvetta  
- vähentää kokonais-CO₂-päästöjä  
- parantaa datakeskuksen energiataseita (esim. ERF/REF-luvut).

Jos hukkalämmön hyödyntäminen ei ole mahdollista, lämpö poistetaan ympäristöön (esim. veteen tai ilmaan) voimassa olevien ympäristönormien mukaisesti – mutta vihreän datakeskuksen tavoitteena on, että **mahdollisimman suuri osa lämmöstä saadaan hyötykäyttöön**.

## P6.7 Esimerkkilaskelmia energiankulutuksesta ja päästöistä

Seuraavat yksinkertaistetut esimerkit havainnollistavat, miten energiankulutus, PUE ja päästöt liittyvät toisiinsa. Numerot ovat suuntaa-antavia ja ne voidaan korvata omilla laskelmillasi.

### Esimerkki 1: Päivittäinen energiankulutus

- IT-kuorma (palvelimet, tallennus, verkko): 500 kW  
- PUE = 1,4 (eli kokonaisteho 500 kW × 1,4 = 700 kW)

Päivittäinen energiankulutus:

- IT-energia: 500 kW × 24 h = 12 000 kWh  
- Kokonaisenergia: 700 kW × 24 h = 16 800 kWh

### Esimerkki 2: CO₂-päästöt eri sähköntuotantotavoilla

Oletetaan päästöintensiteetti:

- fossiilipainotteinen sähkö: 400 gCO₂/kWh (0,4 kgCO₂/kWh)  
- vähäpäästöinen sähkö (ydin + uusiutuvat): 60 gCO₂/kWh (0,06 kgCO₂/kWh)

Päivittäiset päästöt kokonaisenergiasta 16 800 kWh:

- fossiilipainotteinen: 16 800 kWh × 0,4 kgCO₂/kWh = 6 720 kgCO₂  
- vähäpäästöinen: 16 800 kWh × 0,06 kgCO₂/kWh = 1 008 kgCO₂

Erotus on **5 712 kgCO₂ per vuorokausi**, mikä vuodessa vastaa yli 2 000 tonnin eroa.

### Esimerkki 3: Hukkalämmön hyödyntäminen

Oletetaan, että:

- 70 % kokonaisenergiasta voidaan periaatteessa kerätä hukkalämpönä  
- 50 % kerätystä lämmöstä saadaan siirrettyä kaukolämpöverkkoon hyötylämmöksi.

Tällöin päivittäinen hyötylämpö:

- 16 800 kWh × 0,7 × 0,5 = 5 880 kWh / vrk hyötylämpöä.

Jos tämä hyötylämpö korvaa fossiilisilla polttoaineilla tuotettua kaukolämpöä (esim. 200 gCO₂/kWh), päästövähennys on:

- 5 880 kWh × 0,2 kgCO₂/kWh = 1 176 kgCO₂ / vrk.

Näiden esimerkkien avulla voidaan havainnollistaa, miten:

- **energiatehokkuus (PUE)**  
- **sähköntuotannon päästöintensiteetti**  
- **hukkalämmön hyödyntäminen**

yhdessä määrittävät datakeskuksen kokonais-CO₂-päästöt ja vihreyden tason.

---

# P7 – EN 50600-4 -mittarit, sääntely ja muut keskeiset tunnusluvut

Tavoite: syventää M6-moduulin sisältöä ja kuvata, miten EN 50600-4 -standardisarja, PUE/CUE/WUE ja muut mittarit, ympäristöstandardit sekä EU-sääntely liittyvät vihreän datakeskuksen suunnitteluun, käyttöön ja raportointiin.

## P7.1 EN 50600-4 -sarjan rooli datakeskuksissa

EN 50600 -standardiperhe määrittelee datakeskusten suunnittelun, rakentamisen ja käytön periaatteita. Sen **EN 50600-4 -osat** keskittyvät erityisesti:

- energiatehokkuuden mittaamiseen  
- ympäristövaikutuksiin liittyviin tunnuslukuihin  
- mittaustapojen ja raportoinnin yhdenmukaistamiseen.

EN 50600-4 -sarjan idea on, että eri datakeskukset voidaan **verrata keskenään samoilla periaatteilla**: PUE, WUE, CUE ja muut mittarit lasketaan samalla tavalla, ja mittausten rajaukset (mitä otetaan mukaan ja mitä ei) on määritelty selkeästi.

Tämä auttaa:

- datakeskuksen sisäisessä kehittämisessä (omien lukujen vertailu ajan yli)  
- toimittajien ja kumppaneiden vertailussa  
- viranomaisten ja asiakkaiden suuntaan tehtävässä raportoinnissa.

EN 50600-4 ei itsessään sano, mikä PUE tai WUE on “hyvä” – se kertoo, **miten mitataan ja raportoidaan oikein**. Tavoitetasot määritellään yleensä yrityksen, asiakkaan tai muun sääntelyn (esim. EU-direktiivit) pohjalta.

## P7.2 PUE, WUE, CUE ja muut keskeiset mittarit (perustaso)

Datakeskuksen vihreyttä ei voi arvioida yhdellä luvulla, vaan tarvitaan useita mittareita, jotka kuvaavat eri osa-alueita. Keskeisiä tunnuslukuja ovat:

### PUE – Power Usage Effectiveness

**PUE (Power Usage Effectiveness)** kuvaa, kuinka suuri osuus datakeskuksen kokonaisenergiasta päätyy varsinaiseen IT-kuormaan (palvelimet, tallennus, verkko), ja kuinka paljon kuluu “tuki- ja apujärjestelmiin” (jäähdytys, UPS-häviöt, valaistus, jne.).

- Mitä lähempänä arvo 1,0 on, sitä tehokkaampi datakeskus on.  
- PUE ei kerro mitään siitä, miten sähkö on tuotettu – vain siitä, miten tehokkaasti se käytetään konesalin sisällä.

### WUE – Water Usage Effectiveness

**WUE (Water Usage Effectiveness)** kuvaa vedenkulutusta suhteessa IT-kuormaan. Se kertoo:

- kuinka paljon vettä jäähdytys ja mahdolliset muut prosessit kuluttavat  
- miten valitut jäähdytysratkaisut vaikuttavat kokonaisvesijalanjälkeen.

Vihreässä datakeskuksessa pyritään minimoimaan vedenkulutus tai käyttämään mahdollisuuksien mukaan kierrätettyä, harmaata tai muuten kestävällä tavalla hankittua vettä.

### CUE – Carbon Usage Effectiveness ja hiili-intensiteetti

**CUE (Carbon Usage Effectiveness)** yhdistää energian käytön ja sähköntuotannon hiili-intensiteetin. Se kertoo, kuinka paljon hiilidioksidipäästöjä syntyy suhteessa IT-kuormaan.

- Matala CUE tarkoittaa, että joko **kulutus on pieni**, **sähkö on vähäpäästöistä**, tai molempia.  
- CUE täydentää PUE-mittaria: kahdella datakeskuksella voi olla sama PUE, mutta hyvin eri suuri hiilijalanjälki, jos toinen käyttää fossiilipainotteista sähköä ja toinen uusiutuvaa.

### Muut energiankäyttöön liittyvät mittarit

EN 50600-4 -sarja ja muu alan kirjallisuus mainitsevat myös muita tunnuslukuja, kuten:

- **ERF / Energy Reuse Factor** – kuinka suuri osa energiasta (lämpönä) saadaan uudelleenkäyttöön datakeskuksen ulkopuolella.  
- **REF / Renewable Energy Factor** – kuinka suuri osa käytetystä energiasta on uusiutuvista lähteistä.  

Nämä täydentävät PUE/WUE/CUE-mittareita ja auttavat kuvaamaan datakeskuksen kokonaisvaikutusta ympäristöön.

## P7.3 Mistä mittareiden tarvitsemat luvut tulevat

Mittarit eivät synny tyhjästä, vaan ne perustuvat konkreettisiin mittaustuloksiin ja kulutuslukuihin. Tyypillisesti tiedot kerätään:

- **sähkömittareista**: pääsyöttö, UPS, PDU:t, jäähdytysjärjestelmä, pumput, puhaltimet  
- **palvelinkaappien tai laitekohtaisista mittareista**: IT-laitteiden tehonkulutus  
- **vesimittareista**: jäähdytykseen käytetty vesi  
- **monitorointijärjestelmistä (BMS/DCIM)**: lämpötilat, ilmankosteudet, laitekohtaiset tilat  
- **energianhankintasopimuksista ja raportoinneista**: uusiutuvan energian osuus, ostosähkön hiili-intensiteetti.

Mittareiden luotettavuus riippuu suoraan siitä, **kuinka hyvin mittauspisteet on suunniteltu** ja **kuinka kattavasti dataa kerätään**. Vihreän datakeskuksen suunnittelussa mittauspisteet kannattaa huomioida jo varhaisessa vaiheessa, jotta myöhemmin ei tarvitse arvailla tai arvioida kulutuslukuja.

## P7.4 Ympäristöstandardit ja sertifioinnit

Mittarit eivät yksin riitä – tarvitaan myös viitekehyksiä, jotka ohjaavat toimintaa ja auttavat asettamaan tavoitteita. Datakeskuksille ja niiden omistaville organisaatioille keskeisiä standardeja ja sertifiointeja ovat esimerkiksi:

### ISO 50001 – energianhallintajärjestelmä

**ISO 50001** ohjaa yrityksiä rakentamaan järjestelmällisen energianhallintajärjestelmän. Se:

- auttaa tunnistamaan suurimmat energian kuluttajat  
- tukee tavoitteiden asettamista (esim. PUE-taso, kokonaiskulutuksen pienentäminen)  
- ohjaa jatkuvaan parantamiseen (PDCA-sykli: Plan–Do–Check–Act).

Datakeskuksissa ISO 50001 voi toimia “selkärankana”, johon PUE, CUE ja WUE kytketään osaksi laajempaa energianhallintaa.

### LEED, BREEAM ja muut rakennusten ympäristöluokitukset

Rakennus- ja kiinteistöpuolella laajasti käytettyjä luokituksia ovat:

- **LEED** (Leadership in Energy and Environmental Design)  
- **BREEAM** (Building Research Establishment Environmental Assessment Method).

Nämä luokitukset painottavat:

- energiatehokasta rakentamista  
- materiaalivalintoja ja kiertotaloutta  
- vedenkulutusta ja sisäympäristön laatua  
- sijaintia ja liikkumisen ratkaisuja.

Datakeskuksen osalta LEED/BREEAM-sertifiointi voi tukea vihreän imagon lisäksi konkreettista ympäristötyötä ja antaa ulkopuolisen vahvistuksen tehdylle työlle.

### Muut ympäristö- ja johtamisstandardit

Lisäksi voidaan hyödyntää muita standardeja ja viitekehyksiä, kuten:

- **ISO 14001** – ympäristöjohtamisjärjestelmä  
- **ISO 27001** – tietoturvajohtaminen (ei suoraan ympäristöstandardi, mutta tärkeä datakeskuksissa)  
- eri toimialakohtaisia ohjeistuksia ja parhaiden käytäntöjen kokoelmia.

Nämä standardit auttavat varmistamaan, että datakeskuksen suunnittelu ja käyttö ovat **systemaattisia, dokumentoituja ja auditoinnin kestäviä**.

## P7.5 Lainsäädäntö, direktiivit ja raportointivaatimukset

EU-tasolla ja kansallisesti on yhä enemmän sääntelyä, joka vaikuttaa datakeskuksiin. Keskeisiä teemoja ovat:

- **energiatehokkuus**  
- **uusiutuvan energian käyttö**  
- **päästöjen raportointi ja läpinäkyvyys**.

Esimerkkejä:

- **EU:n energiatehokkuusdirektiivi (EED)** ohjaa jäsenmaita parantamaan energiatehokkuutta ja asettaa vaatimuksia suurten energiankäyttäjien seurannalle ja raportoinnille.  
- **uusiutuvan energian direktiivit** kannustavat uusiutuvan energian osuuden kasvattamiseen sähkön tuotannossa.  
- yritysten **kestävyysraportointia** koskevat säädökset (esim. CSRD) lisäävät paineita raportoida energiankulutuksesta, päästöistä ja vähennystoimista.

Datakeskuksia voidaan tarkastella joko:

- **omana yksikkönään** (esim. energiankäyttäjänä ja investointikohteena), tai  
- **osana laajempaa organisaatiota**, jonka päästöraportoinnissa datakeskuksen osuudet näkyvät.

Vihreän datakeskuksen suunnittelussa on tärkeää ymmärtää, **mitä raportointivaatimuksia omalle organisaatiolle kohdistuu**, ja varmistaa, että mittarit ja järjestelmät pystyvät tuottamaan tarvittavat luvut.

## P7.6 Mittarit johtamisen ja raportoinnin välineinä

PUE, CUE, WUE ja muut mittarit ovat hyödyllisiä vasta silloin, kun niitä käytetään **aktiivisesti johtamisessa**. Käytännössä tämä tarkoittaa, että:

- mittareille on asetettu **tavoitetasot** (esim. PUE ≤ 1,4, uusiutuvan energian osuus ≥ 80 %)  
- mittareita **seurataan säännöllisesti** (päivä-, viikko-, kuukausitasolla)  
- tulokset esitetään **selkeinä koosteina** johdolle, teknisille tiimeille ja tarvittaessa asiakkaille  
- poikkeamiin reagoidaan: jos PUE nousee tai CUE heikkenee, selvitetään syyt ja suunnitellaan korjaavat toimenpiteet.

Raportointia voidaan tehdä usealla tasolla:

- **sisäinen raportointi** (IT-johto, kiinteistö-/infrajohto, talousjohto)  
- **asiakasraportointi** (palveluiden hiilijalanjälki, energiatehokkuuslupaukset)  
- **ulkoinen raportointi** (kestävyysraportit, viranomaisraportointi, sertifiointien ylläpito).

Hyvin suunniteltu mittaristo tekee vihreästä datakeskuksesta **läpinäkyvän ja johdettavan** – ei pelkkää markkinointipuhetta.

## P7.7 Mittareiden käyttö kehittämisen ja optimoinnin tukena

Viimeinen askel on käyttää mittareita **aktiiviseen kehittämiseen**, ei vain pakolliseen raportointiin. PUE, CUE, WUE ja muut luvut voivat toimia lähtökohtana:

- **energiansäästöprojektien priorisoinnille** (esim. mikä osa järjestelmästä kuluttaa eniten?)  
- **investointipäätösten tukena** (kannattaako investoida uuteen jäähdytysjärjestelmään, UPS-teknologiaan, lämpöpumppuihin?)  
- **hukkalämmön hyödyntämishankkeiden suunnittelussa** (mitä määriä ja lämpötasoja on käytettävissä ja milloin?)  
- **uusiutuvan energian hankintaan liittyvien sopimusten arvioinnissa**.

Käytännössä mittareiden käytön perusperiaatteet ovat:

1. **Mittaa** riittävän tarkasti ja johdonmukaisesti.  
2. **Visualisoi** tiedot helposti ymmärrettävään muotoon (esim. trendikäyrät, vertailut).  
3. **Tee päätöksiä** mittareiden perusteella – aseta tavoitteita ja toimenpiteitä.  
4. **Seuraa vaikutuksia**: paraniko PUE, pienentyikö CUE, kasvoiko uusiutuvan energian osuus?  
5. **Toista sykliä** (jatkuva parantaminen).

Näin EN 50600-4 -mittarit, ISO- ja ympäristöstandardit sekä EU-sääntely muodostavat **yhtenäisen kokonaisuuden**, jonka avulla vihreää datakeskusta voidaan suunnitella, käyttää, arvioida ja kehittää pitkäjänteisesti.

---

# Lähdeluettelo

1. Cloudflare. (n.d.). *What is a data center?* Cloudflare. Retrieved October 21, 2024, from  
   https://www.cloudflare.com/en-gb/learning/cdn/glossary/data-center/

2. Fingrid. (2022). *High-voltage direct current links connecting Finland to Sweden and Estonia reliable and extensively utilised.*  
   Haettu 19. lokakuuta 2024 osoitteesta  
   https://www.fingrid.fi/sivut/high-voltage-direct-current-links-finland-sweden-estonia/

3. Fingrid. (2022). *Fingrid’s investments safeguard a reliable supply of electricity to the Helsinki metropolitan area and promote significant investment in Finland.*  
   Haettu 19. lokakuuta 2024 osoitteesta  
   https://www.fingrid.fi/sivut/fingrids-investments-safeguard-a-reliable-supply-of-electricity/

4. Manganelli, M., Soldati, A., Martirano, L., & Ramakrishna, S. (2021). Strategies for Improving the Sustainability of Data Centers via Energy Mix, Energy Conservation, and Circular Energy. *Sustainability, 13*(11), 6114.  
   https://doi.org/10.3390/su13116114

5. Digital Infra. (2021). *Data Center Power: A Comprehensive Overview of Energy.*  
   Haettu osoitteesta https://dgtlinfra.com

6. InfoQ. (2022). *The Problem of Power Consumption in Servers.*  
   Haettu osoitteesta https://www.infoq.com

7. FS Community. (2022). *A Complete Guide to Choosing a Power Supply for Your Server.*  
   Haettu osoitteesta https://community.fs.com

8. ServerWatch. (2022). *Data Center Power Consumption: What You Need to Know.*  
   Haettu osoitteesta https://www.serverwatch.com

9. Masanet, E., Shehabi, A., Lei, N., Smith, S., & Koomey, J. (2020). Recalibrating global data center energy-use estimates. *Science, 367*(6481), 984–986.  
   https://doi.org/10.1126/science.aba3758

10. MIT Energy Initiative. (2022). *The future of energy storage: Creating affordable, reliable, deeply decarbonized electricity systems.* MIT News.  
    https://energy.mit.edu/news/energy-storage-important-to-creating-affordable-reliable-deeply-decarbonized-electricity-systems/

11. World Economic Forum. (2021). *These 4 energy storage technologies are key to climate efforts.*  
    https://www.weforum.org/agenda/2021/07/these-4-energy-storage-technologies-are-key-to-climate-efforts/

12. Springer. (2021). *Energy storage techniques, applications, and recent trends: A sustainable solution for power storage.* SpringerLink.  
    https://link.springer.com/article/10.1557/mrs.2021.8

13. Datacenter Knowledge. (2024). *Harnessing waste heat is the latest frontier in data center efficiency.*  
    https://www.datacenterknowledge.com/sustainability/harnessing-waste-heat-is-the-latest-frontier-in-data-center-efficiency

14. Datacenter Review. (2024). *How energy-efficient cooling and heating can decarbonise data centres.*  
    https://datacentrereview.com/2024/05/how-energy-efficient-cooling-and-heating-can-decarbonise-data-centres/

15. Energy Star. (2021). *5 Simple Ways to Avoid Energy Waste in Your Data Center.*  
    https://www.energystar.gov/products/data_center_equipment/5-simple-ways-avoid-energy-waste-your-data-center/virtualize-servers

16. Google. (2024). *DeepMind AI reduces energy used for cooling Google data centers by 40%.*  
    https://blog.google/outreach-initiatives/environment/deepmind-ai-reduces-energy-used-for

17. EdTech Magazine. (2024). *How AI is Affecting Data Center Power Consumption.*  
    https://edtechmagazine.com/higher/article/2024/08/how-ai-affecting-data-center-power-consumption-perfcon

18. Insight. (2024). *Estimating Data Centers’ Carbon Footprint.*  
    https://www.insight.com/content/dam/insight/en_US/pdfs/apc/apc-estimating-data-centers-carbon-footprint.pdf

19. Schneider Electric. (2021). *How Modular Data Centers Help Companies Meet Sustainability Goals.*  
    https://blog.se.com/datacenter/2021/06/30/discover-how-modular-data-centers-help-companies-sustainability-goals/

20. Datacenter Dynamics. (2023). *Embracing the future: Modularization, sustainability, and efficiency in data centers.*  
    https://www.datacenterdynamics.com/en/opinions/embracing-the-future-modularization-sustainability-and-efficiency-in-data-centers/

---

## Muita lähteitä

- **[Google 1]** Barroso, L. A., & Clidaras, J. (2022). *The datacenter as a computer: An introduction to the design of warehouse-scale machines.* Springer Nature.

- **[lvm 1]**  
  http://urn.fi/URN:ISBN:978-952-243-586-6

- **[Fortum 1]**  
  https://www.fortum.fi/tietoa-meista/uutishuone/tietopaketit-medialle/puhtaan-energian-arkkitehti-datakeskuksille

- **[Sharma 1]** Sharma, P., Pegus II, P., Irwin, D., Shenoy, P., Goodhue, J., & Culbert, J. (2017). Design and operational analysis of a green data center. *IEEE Internet Computing, 21*(4), 16–24.

- **[Kontti 1]** Qouneh, A., Li, C., & Li, T. (2011, November). A quantitative analysis of cooling power in container-based data centers. In *2011 IEEE International Symposium on Workload Characterization (IISWC)* (pp. 61–71). IEEE.









