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
