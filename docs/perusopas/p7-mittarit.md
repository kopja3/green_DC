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
