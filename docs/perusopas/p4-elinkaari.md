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
