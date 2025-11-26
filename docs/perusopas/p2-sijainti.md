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
