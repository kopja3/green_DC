# Miksi datakeskus rakennetaan ja minne?  


## Datakeskusten rakentamisen syyt ja sijaintipäätösten perusteet

Datakeskusten merkitys ja kasvava tarve
Datakeskukset ovat sähköisiä tietovarastoja ja laskentakeskuksia, joissa suuria määriä palvelimia ja tietoverkkolaitteita ylläpidetään valvotuissa olosuhteissa. Niiden tehtävänä on:
- Tallentaa, käsitellä ja välittää valtavia määriä dataa
- Pyörittää digitaalisia palveluita, kuten verkkosivustoja, pilvipalveluita, suoratoistoa ja yritysten IT-sovelluksia.

Käytännössä moderni yhteiskunta nojaa datakeskuksiin: **Ne muodostavat digitaalisen infrastruktuurin selkärangan**, joka mahdollistaa internet-palveluiden toiminnan ympäri vuorokauden [1]. Ilman datakeskuksia esimerkiksi sosiaalinen media, verkkokauppa, pilvitallennus ja etätyösovellukset eivät toimisi yhtä luotettavasti.


![Data Center](kuvat/Kansallinen%20konsali.jpg)  
Datakeskuksen konesali CSC:n Kajaanin datakeskusalueella. Konesalissa sijaitsevat palvelimet ovat asennettuina kaappeihin riveihin, joiden välissä on käytävät. *Kuva CSC:n luvalla (CSC – Tieteen tietotekniikan keskus Oy)*.

![LUMI tekninen kerros](kuvat/LUMIwhitespacetekninenkerros.jpg)
Datakeskuksen tekninen kerros: täällä kulkevat kaapeloinnit. Palvelinkaappirivit sijaitsevat tämän kerroksen päällä. *Kuva CSC:n luvalla (CSC – Tieteen tietotekniikan keskus Oy)*

## Miksi datakeskusten tarve kasvaa?

Datakeskusten tarve kasvaa jatkuvasti useista syistä. Yhteiskunnan digitalisoituminen on kiihtynyt, ja yhä suurempi osa viestinnästä, viihteestä ja liiketoiminnasta tapahtuu verkossa. Verkkosisältöjen ja -palveluiden määrän sekä käyttäjien datankulutuksen kasvu (esim. 4K-videoiden suoratoisto, IoT-laitteet, pilvipelipalvelut) lisäävät datankäsittelyn ja tallennuksen tarvetta. Esimerkiksi COVID-19-pandemian aikana verkkopalveluiden käytön kasvu (mm. etäostaminen ja -työskentely) pakotti yritykset laajentamaan tietojenkäsittelykapasiteettiaan merkittävästi. Myös tekoäly, big data -analytiikka ja koneoppiminen lisäävät laskentatehon tarvetta.

Uusien AI-mallien koulutus ja käyttö tapahtuu suurissa datakeskuksissa, mikä vauhdittaa niiden rakentamista [1]. Kansainvälisen energiajärjestön (IEA) mukaan datakeskukset (yhdessä kryptovaluuttalouhinnan ja tekoälyn kanssa) kuluttivat vuonna 2022 noin 460 TWh sähköä (1 terawattitunti = miljardi kilowattituntia; 460 TWh vastaa lähes kahden koko Suomen vuosikulutuksen verran sähköä ja on noin 2 % koko maailman sähkönkulutuksesta), ja digitaalisen datan määrän nopea kasvu edellyttää datakeskusinfrastruktuurin laajentamista ja kehittämistä. Toisin sanoen, digitaalisen tiedon räjähdysmäinen kasvu pakottaa rakentamaan lisää datakeskustilaa sen tallentamiseksi ja käsittelemiseksi. Alan asiantuntijat arvioivatkin, että globaali datakeskuskapasiteetti saattaa jopa kaksinkertaistua muutamassa vuodessa räjähdysmäisesti kasvavan laskentakysynnän vuoksi [1].


## Syyt datakeskusten rakentamiseen: 


Datakeskusten rakentamista motivoivat teknologiset, liiketoiminnalliset ja yhteiskunnalliset syyt. Alla on eritelty nämä näkökulmat:

### 1	Teknologiset syyt: 
Uusi teknologia ja tietoyhteiskunnan kehitys synnyttävät tarpeen kehittyneille datakeskuksille. Pilvipalveluiden yleistyminen merkitsee, että yhä useammat organisaatiot siirtävät IT-toimintojaan omista tiloista suurten palvelinkeskusten hoidettaviksi. Tämä tuo mittakaavaetuja: suuret hyperskaaladatakeskukset* voivat tarjota tehokkaampaa laskentaa ja tallennusta edullisemmin per yksikkö, paremmilla varmistus- ja jäähdytysjärjestelmillä kuin pienet serverihuoneet. Myös luotettavuus ja turvallisuus ovat tärkeitä: modernit datakeskukset on suunniteltu estämään käyttökatkot (redundantit sähkönsyötöt, varmistukset, paloturva jne.), mitä monet yritykset ja julkishallinto eivät voisi itse saavuttaa yhtä korkealla tasolla. 

Lisäksi uudet teknologiat – kuten tekoälylaskenta, esineiden internet (IoT) ja 5G-verkon myötä edge-laskenta – vaativat erikoistunutta infrastruktuuria. Esimerkiksi tekoälyalgoritmien pyörittämiseen tarvitaan paljon sähköä kuluttavia GPU- tai TPU-laitteita *(GPU = Graphics Processing Unit, grafiikkaprosessori; TPU = Tensor Processing Unit, Googlen kehittämä tekoälylaskentaan erikoistunut prosessori)* ja tehokasta jäähdytystä, joten niille rakennetaan tarkoitukseen optimoituja datakeskuksia. Teknologinen kehitys itsessään siis ajaa datakeskusten rakentamista: pysyäkseen kilpailukykyisinä ja ottaakseen käyttöön uusia innovaatioita organisaatiot tarvitsevat yhä enemmän laskentakapasiteettia ja tallennustilaa.

*Hyperskaalattu datakeskus on erittäin suuri, vähintään noin 5000 palvelimen palvelinkeskus, joka on suunniteltu käsittelemään valtavia työkuormia optimoidulla verkkoinfrastruktuurilla ja automatisoiduilla, kahdennetuilla järjestelmillä keskeytyksettömän toiminnan varmistamiseksi. 

### 2️ Liiketoiminnalliset syyt
Yrityksille datakeskusten rakentaminen (tai kapasiteetin vuokraaminen) on strateginen investointi. Digitaalisessa taloudessa data on arvokasta pääomaa ja sen tehokas hyödyntäminen on kilpailuetu. Rakentamalla omia datakeskuksiaan suuret teknologiayritykset (kuten Amazon, Google, Microsoft) voivat hallita paremmin kustannuksia ja palvelun laatua – omassa omistuksessa oleva keskus tarjoaa pitkällä aikavälillä kustannustehokkuutta ja kontrollia verrattuna pelkkään ulkopuolisten pilvipalveluiden käyttöön. 

Myös tietoturva ja yksityisyysnäkökulmat kannustavat: kriittisiä tai arkaluonteisia tietoja käsittelevät toimijat (esim. pankit, terveydenhuolto, viranomaiset) saattavat haluta omat kotimaiset datakeskukset varmistaakseen, että data pysyy määrätyn lainkäyttöalueen sisällä ja että heillä on täysi hallintavalta siihen. Lisäksi asiakaskokemus ja suorituskyky ovat keskeisiä liiketoiminnallisia syitä: Yritys voi sijoittaa palvelimiaan lähemmäs suuria asiakasmassoja rakentaen alueellisia datakeskuksia, mikä vähentää viivettä (latenssia) ja parantaa palvelun nopeutta loppukäyttäjille. Esimerkiksi globaalisti toimiva suoratoistopalvelu tai sosiaalisen median yhtiö tarvitsee datakeskuksia eri maanosissa voidakseen tarjota sisällön nopeasti paikallisille käyttäjille. 

Datakeskusten rakentaminen on myös suoraa liiketoimintaa: pilvipalveluiden tarjoajat ja co-location-toimijat** rakentavat jatkuvasti uusia keskuksia vastatakseen kasvavaan kysyntään ja houkutellakseen uusia asiakkaita. Samalla he pyrkivät sijoittamaan keskukset niin, että ne täyttävät asiakkaiden lakisääteiset vaatimukset (esim. GDPR edellyttää tietojen säilyttämistä tietyillä alueilla. GDPR = General Data Protection Regulation, EU:n yleinen tietosuoja-asetus, joka määrittää, miten henkilötietoja saa kerätä, käsitellä ja säilyttää) ja palvelutasovaatimukset. Tiivistetysti: Yritykset investoivat datakeskuksiin kasvattaakseen kapasiteettia, parantaakseen palvelua ja turvatakseen liiketoimintansa jatkuvuuden digitaalisessa maailmassa.

**Co-location-datakeskus on konesali, jossa yritys tai organisaatio vuokraa tilaa ja valmiin infrastruktuurin omille palvelimilleen ja IT-laitteilleen, hyödyntäen datakeskuksen tarjoamaa sähkönsyöttöä ja varavoimaa, jäähdytystä, verkkoyhteyksiä, kaapelointeja ja fyysistä turvaa, mutta säilyttäen täyden hallinnan omasta laitteistostaan ja ohjelmistoistaan.

### 3️ Yhteiskunnalliset syyt
Yhteiskunnan digitalisoituminen ja kansalaisten odotukset luovat painetta datakeskusten rakentamiseen. Julkishallinto kehittää sähköisiä palveluita (kuten kansallisia terveysarkistoja, vero- ja lupapalveluita, jne.), jotka edellyttävät kotimaisia luotettavia datakeskuksia. Monissa maissa on herännyt tietoisuus digitaalisen omavaraisuuden tärkeydestä: halutaan varmistaa, että kriittinen data ja viestintäverkot sijaitsevat turvallisesti maan rajojen sisäpuolella. Esimerkiksi GDPR:n myötä yritykset ovat varmistaneet, että eurooppalaisten käyttäjien tiedot säilytetään EU-alueen datakeskuksissa vaatimusten täyttämiseksi (tästä syystä kansainväliset pilvipalvelujätit rakentavat keskuksia myös Eurooppaan). 

Yhteiskunnallisesta näkökulmasta datakeskukset tuovat myös taloudellisia hyötyjä: niitä pidetään uutena kriittisenä infrastruktuurina, jonka ympärille voi kehittyä taloudellista toimeliaisuutta. Datakeskusinvestoinnit luovat työpaikkoja sekä rakennusvaiheessa että operointivaiheessa (tarvitaan mm. teknikot, insinöörit ja tukipalvelut). Vaikka automatisointi on pitkällä datakeskuksissa, silti yhden suuren keskuksen käyttö vaatii paikallista asiantuntijahenkilöstöä, ja hyvin palkatut ICT-työpaikat tuovat tuloja alueelle. Rakentaminen tuo myös merkittäviä pääomavirtoja: yhden modernin hyperskaaladatakeskuksen rakennuskustannukset voivat olla satoja miljoonia tai jopa miljardi euroa, mikä näkyy paikallisessa taloudessa vilkastumisena. Lisäksi datakeskukset kasvattavat paikallista verokertymää – kiinteistöveroista ja laitteistojen arvon perusteella perittävistä veroista – ja nämä verotulot voivat tukea julkisia palveluita, kuten kouluja ja terveydenhuoltoa. 

Paikallinen infrastruktuuri (sähköverkot, tietoliikenneyhteydet, tiet) paranee usein keskuksen myötä, mistä on hyötyä muillekin yrityksille ja asukkaille. Myös osaamisen leviäminen on yhteiskunnallinen hyöty: datakeskusten ympärille muodostuu teknologiaekosysteemejä ja kumppaniverkostoja, jotka voivat synnyttää uusia yrityksiä ja koulutusmahdollisuuksia [2]. Esimerkiksi suuryritykset voivat tehdä yhteistyötä oppilaitosten kanssa kouluttaakseen datakeskusosaajia ja inspiroidakseen nuoria IT-alalle. Yhteenvetona, yhteiskunta hyötyy datakeskuksista digitaalisten palveluiden saatavuutena, talouskasvuna sekä infrastruktuurin ja osaamisen kehittymisenä – siksi myös julkinen valta usein tukee datakeskushankkeita (esim. tarjoamalla kaavoitusetuja tai sähkön verohuojennuksia datakeskuksille, kuten Suomessa on tehty).

On kuitenkin hyvä todeta, että datakeskusten yleistyminen tuo myös haasteita, kuten suuren energiankulutuksen ja ympäristövaikutukset. Nämä on pyritty ratkaisemaan mm. hyödyntämällä uusiutuvaa energiaa ja hukkalämmön talteenottoa. Esimerkiksi eräissä suomalaisissa datakeskuksissa palvelimien tuottama lämpö kerätään talteen ja käytetään kaukolämpöverkossa asuntojen lämmittämiseen, jolloin keskus sulautuu osaksi paikallista energiajärjestelmää.

## Datakeskuksen sijaintipäätökseen vaikuttavat tekijät

Datakeskuksen sijantia suunniteltaessa tulisi ottaa huomioon useita tekijöitä, jotta keskus olisi taloudellisesti kannattava, tehokas ja turvallinen. Tärkeitä sijaintikriteereitä ovat mm.:

-Sähköeneregian saatavuus ja hinta 

-Imasto

-Maantiede ja tietoliikenneyhteydet

-Toimintaympäristön vakaus 

-Infrastruktuuri 

-Työvoiman saatavuus

Alla on eritelty nämä tekijät:

### **Sähköenergian saatavuus ja hinta**

Sähkön saatavuus ja hinta ovat ehkä tärkein yksittäinen sijaintipäätöstä ohjaava tekijä datakeskuksille. Koska suuret datakeskukset kuluttavat valtavasti sähköä (yksi iso keskus voi käyttää yhtä paljon sähköä kuin kymmeniätuhansia kotitalouksia ), on elintärkeää, että sijaintipaikassa on riittävästi sähkökapasiteettia ja mieluiten edullista energiaa. Alueet, joilla on ylimääräistä sähköntuotantoa tai halpaa energiaa, houkuttelevat datakeskuksia. Esimerkiksi Pohjois-Ruotsin Luleåssa on Euroopan halvimpia sähköhintoja johtuen runsaasta vesivoimasta – tämä oli yksi syy Facebookin datakeskuksen sijoittumiseen sinne [6]. Vastaavasti monet teknologiajätit suosivat Pohjoismaita, koska uusiutuvaa energiaa (vesi-, tuuli- ja ydinvoimaa) on runsaasti tarjolla kohtuuhintaan.

Pelkkä edullisuus ei riitä, myös sähköverkon luotettavuus ja kapasiteetti painavat vaakakupissa. Datakeskus tarvitsee vakaan, keskeytyksettömän sähkönsyötön, joten sijaintipaikan sähköinfrastruktuurin on oltava vikasietoinen ja riittävän vahva. Usein keskuksia rakennetaan lähelle suuria sähköasemia tai tuotantolaitoksia, jotta sähköä saadaan suoraan ilman pitkää siirtoetäisyyttä. Joissain tapauksissa datakeskustoimijat sijoittavat keskuksia tarkoituksella sähkön tuotantopaikkojen viereen: esimerkiksi Yhdysvalloissa on suunniteltu datakeskuksia tuulipuistojen ja aurinkovoimaloiden yhteyteen Teksasissa, jotta keskukset voivat hyödyntää muutoin ylijäävää puhdasta sähköä suoraan tuotantopaikalla. 

Uusiutuvan energian saatavuus onkin kasvava kriteeri, sillä yritykset tavoittelevat hiilineutraaliutta – monet valitsevat sijainteja, joissa ne voivat solmia pitkäaikaisia uusiutuvan energian sopimuksia (PPA = Power Purchase Agreement, pitkäaikainen sähkönostosopimus, jossa ostaja ja energiantuottaja sopivat ennalta sähkön hinnasta ja toimitusmääristä vuosiksi eteenpäin) taatakseen edullisen ja vihreän sähkön saannin vuosiksi eteenpäin. Suomessa ja muissa Pohjoismaissa valtio on lisäksi tukenut datakeskuksia alentamalla niiden sähköveroa tai tarjoamalla muita energiakustannuksia keventäviä toimia houkutellakseen investointeja. 

Yhteenvetona: halpa, puhdas ja luotettava energia on datakeskuksen sijainnille yhtä tärkeää kuin raaka-aineiden saatavuus on perinteiselle tehtaalle.

### **Viileä ilmasto ja ympäristötekijät**

Ilmasto vaikuttaa suoraan datakeskuksen jäähdytystarpeeseen. Palvelimet tuottavat runsaasti lämpöä, ja niiden pitämiseksi toimintalämpötilassa tarvitaan jäähdytystä. Siksi viileä ilmasto on etu: viileillä alueilla voidaan hyödyntää ulkoilmaa tai luonnollista kylmyyttä jäähdytyksessä (ns. free cooling), mikä pienentää sähköä kuluttavien ilmastointikoneiden tarvetta. Pohjoiset alueet, joissa ilmasto on suurimman osan vuodesta kylmä, mahdollistavat huomattavia säästöjä jäähdytyskustannuksissa. Viileän ilmaston lisäksi myös kuiva ilma on suotuisa (korkea ilmankosteus voi ruostuttaa laitteita ja heikentää jäähdytystehoa), joten monet keskukset sijaitsevat alueilla, joilla ilman kosteus on hallittavissa.

Esimerkiksi Facebook mainitsi Luleån valinnan syyksi juuri pakkasilman hyödyntämisen palvelinten jäähdyttämisessä – arktinen sijainti 100 km napapiirin eteläpuolella takaa lähes ympärivuotisen luonnonjäädytyksen. Samoin Google käyttää Suomen Haminassa sijaitsevassa datakeskuksessaan suoraan Suomenlahden kylmää merivettä jäähdytykseen innovatiivisella tavalla. 

Ympäristötekijöihin kuuluu myös luonnonolosuhteiden vakaus. Datakeskukselle on kriittistä välttää sijainteja, joissa on suuri luonnonkatastrofien riski. Maanjäristykset, tulvat, hurrikaanit, metsäpalot tai muut ääri-ilmiöt voivat pahimmillaan rikkoa palvelinlaitteistoa tai katkaista datakeskuksen toiminnan pitkäksi aikaa. Tästä syystä monet datakeskukset sijoitetaan maantieteellisesti vakaisiin paikkoihin: esimerkiksi Suomessa kallioperä on vakaa ja maanjäristykset äärimmäisen harvinaisia, mikä on etu verrattuna vaikkapa Tyynenmeren maihin. Samoin Pohjoismaissa ei esiinny hirmumyrskyjä tai tornadon kaltaisia tuhoisia sääilmiöitä siinä määrin kuin joillain muilla alueilla. 

Toimintavarmuuden kannalta ihanteellinen paikka on siis ympäristöriskien kannalta “tylsä” – esimerkiksi kaukana mannerlaattojen saumakohdista, poissa tulvien alueilta ja korkealla merenpinnasta, jotta ilmastonmuutoksen aiheuttama merenpinnan nousu tai myrskytulvat eivät uhkaa. Maantieteellinen vakaus ja ennustettava ilmasto vähentävät varautumiskustannuksia ja vakuutuskuluja datakeskuksen elinkaaren aikana.

### **Maantieteellinen sijainti ja verkkoyhteydet**

Datakeskuksen on oltava hyvin kytköksissä internetin runkoverkkoihin, joten maantieteellinen sijainti kulkee käsi kädessä tietoliikenneyhteyksien kanssa. Ihanteellisella paikalla on lyhyt viive (latenssi) suuriin liikenteen solmupisteisiin ja asiakkaiden luokse. Tästä syystä monet datakeskukset keskittyvät tietoliikenteen solmukohtiin: esimerkiksi Frankfurt, Lontoo, Amsterdam ja Pariisi (ns. FLAP-markkinat) ovat perinteisesti olleet Euroopan suurimpia datakeskuskeskittymiä, koska niissä risteävät monet internet-kaapelit ja operaattorit. Viime aikoina Pohjoismaat ovat kuitenkin nousseet varteenotettaviksi vaihtoehdoiksi, koska ne tarjoavat sekä hyvät yhteydet että muita etuja (ilmasto, vakaus jne.) [7]. 

Suomi on esimerkiksi maantieteellisesti idän ja lännen välissä, ja täältä on erittäin nopeat yhteydet sekä Keski-Eurooppaan että Aasiaan; Helsinki–Frankfurt-datayhteys on Pohjoismaiden nopeimpia. Datakeskuksen yhteyksien suunnittelussa huomioidaan läheisyys runkokuituyhteyksiin ja internet exchange -pisteisiin: lyhyt etäisyys kuituverkkoon tarkoittaa, että dataa voidaan siirtää suurella kaistalla ja pienellä viiveellä maailmalle. Siksi datakeskus saatetaan rakentaa esimerkiksi lähelle suuria kaapelireittejä tai merikaapelin laskeutumispistettä, taikka sellaiseen kaupunkiin, jossa on useiden operaattorien välinen solmupiste.
Lisäksi monet yritykset haluavat tuoda palvelunsa maantieteellisesti lähelle käyttäjiä vähentääkseen latenssia. Tätä varten globaaleilla pilvipalveluyrityksillä on datakeskuksia eri alueilla (esim. ”reunaverkon” datakeskukset), jotta vaikkapa Aasiassa olevien asiakkaiden pyynnöt voidaan käsitellä Aasian sisällä sen sijaan, että tieto matkustaisi mannerten yli. 

Maantieteellinen sijainti vaikuttaa myös juridisiin tekijöihin: yritys saattaa perustaa datakeskuksen tiettyyn maahan palvellakseen kyseisen maan asiakkaita ja noudattaakseen paikallisia lakeja (esim. sosiaalisen median yritys rakentaa datakeskuksen vaikkapa Intiaan, jos laki vaatii, että Intian kansalaisten data säilytetään maan rajojen sisällä).

Verkkoyhteyksien redundanssi on niin ikään huomioitava: hyvä sijainti tarjoaa useita erilaisia yhteysreittejä (monien eri teleoperaattorien kautta), jotta yhden yhteyden vikaantuessa datakeskuksen liikenne voidaan ohjata toista reittiä pitkin. Esimerkiksi carrier-neutral-datakeskusalueet, joilla on runsaasti valinnanvaraa yhteyksien suhteen, ovat houkuttelevia. Myös viestintäinfran laajennettavuus on plussaa – alueella tulisi olla kapasiteettia lisätä kuituyhteyksiä ja verkkolaitteistoa datakeskuksen tarpeiden kasvaessa.

### **Lainsäädäntö, turvallisuus ja poliittinen vakaus**

Datakeskukset ovat pitkän aikavälin investointeja, joten maan poliittinen ja lainsäädännöllinen vakaus on tärkeää. Toimintaympäristön tulee olla ennustettava: Sijoittajat ja yritykset suosivat maita, joissa hallinto on vakaa, sopimusten pitävyys taattu ja korruptio vähäistä. Esimerkiksi Suomi mainitaan kansainvälisissä vertailuissa yhtenä maailman vakaimmista ja vähiten korruptoituneista maista [5], mikä lisää luottamusta datakeskusten pitkäjänteiseen operointiin. 

Poliittinen vakaus tarkoittaa myös sitä, että sisäinen tai ulkoinen turvallisuustilanne on hyvä – maassa ei ole konflikteja tai suuria levottomuuksia, jotka voisivat uhata infrastruktuuria. Lisäksi vakaa oikeusvaltio takaa, että omistusoikeudet ja immateriaalioikeudet ovat turvassa. Nämä tekijät ovat kriittisiä etenkin ulkomaisille yrityksille, jotka miettivät miljardi-investointeja: he haluavat varmuuden, että esimerkiksi hallitus ei tule yllättäen takavarikoimaan omaisuutta tai ettei lainsäädäntö radikaalisti muutu haitalliseksi. Poliittisesti vakaa maa takaa myös, että terrorismi- tai sabotaasiriski on alhaisempi ja että viranomaisilta saa apua kriisitilanteissa.

Lainsäädännön suotuisa ilmapiiri datakeskuksille voi ilmetä monella tapaa. Jotkin maat ja alueet tarjoavat verokannustimia: esimerkiksi Yhdysvalloissa monet osavaltiot vapauttavat datakeskuksen laitehankinnat myyntiverosta tietyksi ajaksi, ja Suomessa datakeskuksille on säädetty alempi sähkövero luokitus, mikä alentaa operointikustannuksia. 

Tietosuojalait ja muut regulaatiot tulee myös huomioida sijaintia valittaessa. Yrityksen pitää voida noudattaa asiakkaidensa vaatimuksia. EU-alueella toimiville on tärkeää, että datakeskus sijaitsee EU:n lainsäädännön piirissä (GDPR-yhteensopivuus). Toisaalta joissain maissa saattaa olla datakeskuksia hankaloittavia lakeja, kuten rajoituksia datan siirrolle tai korkeita sähköveroja, mikä voi vähentää houkuttelevuutta. Yritysystävällinen hallinto, joka on ICT-myönteinen, nopeuttaa myös käytännön asioita: Rakennusluvat, kaavoitus ja muut viranomaisprosessit sujuvat jouhevammin, kun hallinto ymmärtää datakeskushankkeiden arvon. Esimerkiksi Suomessa hallinto on suhtautunut suopeasti kansainvälisiin datakeskustoimijoihin ja pitänyt kustannukset maltillisina, mikä on tehnyt maasta houkuttelevan sijoituskohteen.

Turvallisuus liittyy sekä fyysiseen turvallisuuteen että kyberturvallisuuteen. Fyysisessä mielessä datakeskukselle valitaan paikka, jossa riski vandalismille tai rikollisuudelle on pieni – usein vartioitu teollisuusalue tai syrjäisempi seutu, jonne on kontrolloitu pääsy. Moni datakeskus sijaitsee tarkoituksella hieman syrjässä suurkaupunkien keskustoista, paitsi verkkoviiveen minimoimiseksi myös siksi, että rauhallisemmalla sijainnilla on helpompi ylläpitää korkean turvatason aidat, kameravalvonnat ja muut fyysiset suojauskeinot.  Kyberturvallisuuden kannalta merkitystä on enemmän keskuksen operoinnilla kuin sijainnilla, mutta esim. lainsäädäntö vaikuttaa siihenkin: jossain maissa on tiukempia vaatimuksia varautumisesta (kuten vaaditaan varavoimaa X tunniksi, paloturvallisuusstandardeja ym.), mikä voi vaikuttaa kustannuksiin.

### **Saatavilla oleva infrastruktuuri ja osaava työvoima**

Hyvä sijainti tarjoaa valmiiksi kehittyneen infrastruktuurin. Tämä tarkoittaa esimerkiksi sitä, että alueella on riittävän suuret sähkönsiirtolinjat, vesi- ja viemäriverkosto (jos käytetään vedenjäähdytystä), tietoliikennekanavat sekä tiet ja logistiikka toimivalla tasolla. Alueet, joilla on teollinen infrastruktuuri valmiina, ovat etulyöntiasemassa: esimerkiksi vanhan tehtaan tai teollisuusalueen yhteyteen tuleva datakeskus voi hyödyntää olemassa olevia sähköliittymiä, kuituyhteyksiä ja tieverkostoa. Samoin on etu, jos tontilla tai lähistöllä on runsaasti tilaa laajentua – datakeskukset saattavat tarvita lisää rakennusvaiheita tulevaisuudessa, joten sijainnin pitää sallia kasvun (sekä fyysisesti että kaavoituksellisesti). Moni datakeskus alkaa yhdestä hallista mutta laajenee kampukseksi. Tästä syystä seudut, joissa on edullista maa-alaa tarjolla ja myötämieliset kaavoitusmahdollisuudet, pärjäävät kilpailussa [3],[4].

Osaavan työvoiman saatavuus on toinen ratkaiseva tekijä. Vaikka datakeskukset ovat pitkälti automatisoituja, ne tarvitsevat pätevää henkilökuntaa ylläpitoon, valvontaan, korjauksiin ja tietohallintaan. Sijainnilta toivotaan, että lähettyvillä on ICT-alan osaajia tai että alueella on vetovoimaa houkutella asiantuntijoita muuttamaan sinne. Tyypillisesti vahvan teknologiayliopiston tai -yhteisön läheisyys katsotaan eduksi: esimerkiksi pääkaupunkiseudulla tai teknologiahubien lähellä on helpompi löytää verkkoinsinöörejä, järjestelmäasiantuntijoita ja muuta henkilöstöä datakeskuksen tarpeisiin. Jo Facebook mainitsi aikoinaan Luleån valttina “lahjakkaan paikallisen työvoiman” saatavuuden yhtenä tekijänä kaupungin valinnassa. Mikäli sijainti on hyvin syrjäinen, datakeskusyritykset joutuvat panostamaan henkilöstön koulutukseen tai tuomaan työntekijöitä muualta, mikä voi lisätä kustannuksia. Toisaalta datakeskushankkeet voivat itsessään kehittää paikallista osaamista – yhteistyö oppilaitosten kanssa ja erilaisten harjoitteluohjelmien kautta ne rakentavat sitä työvoimapohjaa, jota ne tarvitsevat. Esimerkiksi Google on useissa maissa osallistunut paikallisiin koulutushankkeisiin varmistaakseen, että tulevaisuudessa on riittävästi datakeskusammattilaisia [3],[4]. 

Yhteenvetona, datakeskuksen sijoituspaikan valinta on monen tekijän optimointia. Sen tulee yhdistää tekniset tekijät (energia, viileys, yhteydet) liiketoiminnallisiin (kustannukset, lainsäädäntö) ja inhimillisiin tekijöihin (työvoima, yhteisön tuki). Paikka, joka maksimaalisesti hyödyttää näitä kaikkia, on yleensä voittaja kilpailussa datakeskusinvestoinneista.

### **Esimerkkejä datakeskuksista ja niiden sijaintiperusteista**

Meta (Facebook) – Luleå, Ruotsi: Yksi tunnetuimmista esimerkeistä on Metan (Facebookin) datakeskus Luleåssa Ruotsissa. Se avattiin vuonna 2013 ja oli yhtiön ensimmäinen keskus Yhdysvaltojen ulkopuolella. Luleån sijainti tarjosi poikkeuksellisen hyvät olosuhteet: kaupungin läpi virtaava joki tuottaa lähes rajattomasti halpaa vesivoimaa, mikä teki sähköstä edullista ja uusiutuvaa. Lisäksi Luleå on hyvin kylmä ympäri vuoden (lähellä napapiiriä), joten ulkoilma viilentää palvelimia tehokkaasti suuren osan ajasta [6]. Facebookin edustaja on todennut, että Luleå tarjosi “parhaan yhdistelmän resursseja: sopiva ilmasto ekologiseen jäähdytykseen, puhtaat energiavarat, saatavilla olevaa maa-alaa, osaava paikallinen työvoima ja liiketoimintaystävällinen ympäristö”. Myös Ruotsin poliittinen vakaus ja kehittynyt infrastruktuuri tukivat valintaa. Tämä esimerkki havainnollistaa, kuinka useat tekijät – ilmasto, energia, ihmiset ja hallinto – yhdessä ratkaisevat sijainnin.

Google – Hamina, Suomi: Google operoi yhtä Euroopan suurimmista datakeskuksista Haminassa Suomessa. Google valitsi Haminan alun perin vuonna 2009, kun yhtiö osti siellä sijaitsevan entisen paperitehtaan ja muunsi sen moderniksi datakeskukseksi. Sijaintipäätöksen perusteina olivat Suomen viileä ilmasto ja ainutlaatuinen mahdollisuus käyttää merivettä jäähdytykseen: Haminan keskus hyödyntää suoraan Suomenlahden kylmää merivettä palvelinten viilentämisessä, mikä vähentää merkittävästi perinteisen jäähdytyksen tarvetta. Lisäksi Suomesta löytyi vankka sähköverkko ja paljon uusiutuvaa energiaa (vesi- ja tuulivoimaa) kilpailukykyiseen hintaan. Suomen hallinto on ollut datakeskuksille myönteinen tarjoamalla mm. alennetun sähköveron [5], ja maan sijainti EU:n ja euroalueen jäsenenä tuo juridista selkeyttä kansainvälisille toimijoille. Google on maininnut Suomen vakaan yhteiskunnan ja osaavan työvoiman myös eduiksi – maassa on vahvaa ICT-osaamista ja luotettava toimintaympäristö. Kaiken tämän ansiosta Google on laajentanut Haminan datahalliaan useaan otteeseen ja investoinut Suomeen jo miljardi euroa. Haminan tapaus osoittaa, että jopa suhteellisen pieneen kaupunkiin voi rakentua globaalisti merkittävä datakeskuskeskittymä, jos olosuhteet (kuten vanha tehdasinfrastruktuuri, jäähdytysmahdollisuus ja sähköntuotanto) osuvat kohdilleen.

LUMI – Kajaani, Suomi: LUMI on yksi maailman tehokkaimmista supertietokoneista ja Euroopan suurin tutkimuskäyttöön rakennettu datakeskus, joka sijaitsee Kajaanissa. LUMI hyödyntää Suomen kylmää ilmastoa, vesivoimaa ja jo olemassa olevaa infrastruktuuria, kuten entisen paperitehtaan tiloja, mikä tekee siitä ekologisesti ja taloudellisesti kestävän ratkaisun. Kajaanin sijainti mahdollistaa tehokkaan jäähdytyksen luonnollisilla keinoilla ja hyödyntää paikallista energiaa, minkä ansiosta LUMI toimii lähes täysin hiilineutraalisti. Lisäksi LUMI tuo merkittävää alueellista hyötyä työllisyyden ja osaamisen kehityksen kautta ja vahvistaa Suomen asemaa huippututkimuksen keskuksena.

Microsoft – Pohjoismaat: Myös Microsoft on ilmoittanut suurista investoinneista datakeskuksiin Pohjoismaissa. Esimerkiksi yhtiö on rakentamassa uusia keskuksia Etelä-Suomen Espooseen ja Kirkkonummelle. Perusteluina ovat pitkälti samat tekijät: Suomen kylmä ilmasto, vahva sähköinfrastruktuuri ja poliittinen vakaus luovat hyvän pohjan, ja Microsoft aikoo pyörittää keskuksiaan 100 % uusiutuvalla energialla. Pohjoismaissa on myös kunnianhimoiset ilmastotavoitteet ja mahdollisuuksia hyödyntää datakeskusten hukkalämpöä kaukolämpöverkossa, mikä on linjassa Microsoftin kestävän kehityksen tavoitteiden kanssa. Samalla Suomen asema turvallisena EU-maana takaa, että Microsoftin asiakkaiden dataa voidaan säilyttää paikallisesti GDPR:n vaatimusten mukaisesti. Myös Ruotsissa ja Tanskassa Microsoft on sijoittanut keskuksia – esimerkiksi Ruotsissa ovat vahvasti käytössä maan runsaat uusiutuvat energialähteet (kuten tuulivoima). Nämä esimerkit osoittavat, että Pohjoismaat yleisesti vetävät hyperskaalatoimijoita puoleensa: kansainväliset yhtiöt arvostavat alueen viileää ympäristöä, edullista vihreää energiaa ja vakaita olosuhteita, minkä ansiosta alueelle on ennustettu suorastaan datakeskusten “buumia” seuraavina vuosina.

Muut esimerkit: Yhdysvalloissa Loudoun County Virginiassa (lempinimeltään “Data Center Alley”) on maailman suurin datakeskittymä. Sijainnin etuina ovat olleet erinomainen verkkojen risteyskohta (lähellä internetin runkoverkon solmua), kohtuulliset sähkökustannukset sekä osavaltion tarjoamat verohuojennukset datakeskusrakentajille. Irlanti on toinen tunnettu keskittymä: Dublinia ympäröivä alue on houkutellut hyperskaalakeskuksia, koska Irlannissa on englanninkielinen liiketoimintaympäristö, EU-jäsenyys, viileä meri-ilmasto sekä aiemmin hyvin matala yritysverotus. Islanti puolestaan markkinoi itseään datakeskuspaikkana 100 % uusiutuvan energian (geoterminen ja vesivoima) ja kylmän ilmastonsa vuoksi – siellä toimii datakeskuksia, jotka hyödyntävät vulkaanista lämpöä sähköntuotantoon ja arktista ilmaa jäähdytykseen. Nämä kaikki esimerkit korostavat, miten kustannus- ja tehokkuusedut sekä riskien minimointi ohjaavat datakeskusten maantiedettä.
________________________________________

### *** Yhteenvetona***: 
Datakeskusten rakentaminen on olennainen osa digitaalisen yhteiskunnan infrastruktuuria, ja niiden tarve kasvaa dataintensiivisen tulevaisuuden myötä. Rakentamispäätöksiin vaikuttavat niin teknologian trendit (pilvipalvelut, AI), liiketoimintatarpeet (kustannustehokkuus, palvelun laatu) kuin yhteiskunnalliset tekijät (taloushyödyt, regulaatio). Sijaintia valitessa punnitaan huolellisesti energian hinta ja lähde, ilmaston tarjoamat edut, sijainnin tarjoamat tietoliikenneyhteydet, alueen vakaus ja säännökset sekä tarvittavan infrastruktuurin ja osaajien olemassaolo. Parhaat datakeskusten sijaintipaikat tarjoavat optimaalisen yhdistelmän näitä tekijöitä – niissä data virtaa nopeasti ja turvallisesti, palvelimet pysyvät viileinä uusiutuvan energian tuottaman sähkön avulla toimivilla energiatehokkailla jäähdytysjärjestelmillä, toimintaympäristö on vakaa ja kustannukset hallinnassa. Tällaisissa paikoissa rakennetut datakeskukset auttavat vastaamaan maailman kasvavaan digitaalisen tiedonkäsittelyn tarpeeseen tehokkaasti ja kestävästi.

Lähteet:
[1] GPRS – Understanding the Data Center Construction Boom,  https://www.gp-radar.com/article/understanding-the-data-center-construction-boom

[2]
Golden Shovel Agency. (2023, March 21). Uncovering the top benefits of attracting a data center to your community. Golden Shovel Agency. https://www.goldenshovelagency.com/news/p/item/52422/uncovering-the-top-benefits-of-attracting-a-data-center-to-your-community

[3]
Flexential. (2021, August 17). Essential considerations for effective data center site selection. Flexential. https://flexential.com/resources/blog/essential-considerations-effective-data-center-site-selection

[4]
DC Byte. (n.d.). Choosing a data centre location (APAC). DC Byte. https://www.dcbyte.com

[5]
Telia Finland. (n.d.). Vakaa kotimaa datakeskuksille – 4 syytä miksi kannattaa sijoittaa Suomeen. Telia Finland. https://www.telia.fi/yrityksille/artikkelit/artikkeli/vakaa-kotimaa-datakeskuksille-4-syyta-miksi-kannattaa-sijoittaa-suomeen

[6]
Vaughan, A. (2011, October 27). Facebook builds ‘green’ datacentre in Sweden. The Guardian. https://www.theguardian.com/environment/2011/oct/27/facebook-green-datacentre-sweden

[7]
Pexapark. (2023, April 13). Breaking down the data center surge in the Nordics: Key players, trends, and PPAs. Pexapark. https://pexapark.com/blog/prmc-breaking-down-the-data-center-surge-in-the-nordics-key-players-trends-and-ppas/

Jarmo Koponen
