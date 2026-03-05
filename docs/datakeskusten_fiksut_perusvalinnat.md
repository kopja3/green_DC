Itseopiskelumateriaali datakeskusten ilmastovaikutukset ja fiksut perusvalinnat
Datakeskukset ovat digipalvelujen “konehuoneita”: ne tekevät laskennan ja datan käsittelyn, mutta samalla ne käyttävät paljon sähköä, ja juuri se on useimmiten suurin ilmastovaikutusten lähde.   
Ilmastovaikutus ei synny “datakeskuksesta itsestään”, vaan siitä, kuinka paljon sähköä kuluu ja millä sähkö tuotetaan (hiilipitoinen vs. vähähiilinen sähköntuotanto).   
Toinen iso tekijä on arkinen: kuinka tehokkaasti datakeskuksien laskentakapasiteettia käytetään. Vajaakäyttö on kuin pitäisit auton moottoria tyhjäkäynnillä koko päivän, energia kuluu ilman näkyvää höytyä.   
Lisäksi myös rakennus ja laitteet aiheuttavat ilmastovaikutuksia jo ennen kuin ensimmäinenkään bitti liikkuu: raaka-aineet, valmistus, kuljetus ja elinkaaren loppu kuuluvat kokonaiskuvaan. Siksi käyttöikä, uudelleenkäyttö ja kiertotalous merkitsevät.  
Tämän oppaan tavoite on yksinkertainen: ymmärrä mistä päästöt syntyvät ja opi periaatteet, joilla niitä pienennetään käytännössä.
1. Mikä on datakeskus
Osaat selittää datakeskuksen perusidean (tilat + IT + tukijärjestelmät).
Datakeskus on fyysinen ympäristö, jossa tuotetaan digitaalisia palveluja laskennan, tallennuksen ja tietoliikenteen avulla. Varsinaisen työn tekevät IT‑laitteet (palvelimet, tallennus, verkkolaitteet), ja “taustalla” toimivat tukijärjestelmät (sähkönsyöttö, sähkönsyötön varmistukset, jäähdytys, automaatio, valvonta ja turvallisuus), jotta palveluja voidaan tuottaa ympäri vuorokauden jatkuvasti. 
Ilmasto ja isompi kuva:
Digitaalinen palvelu muuttuu sähköksi ja lämmöksi datakeskuksessa. Periaate: pyri tuottamaan sama palvelu vähemmällä sähköllä ja puhtaammalla sähköllä.
Neuvo: ajattele datakeskusta “palvelutehtaana”, jossa tehokkuus ja sähkön laatu ratkaisevat. Väärinkäsitys: “vihreys” tulee rakennuksesta, useimmiten se tulee käytön aikaisesta sähköstä. 
Tämän oppaan punainen lanka on kolme arkijärkistä kysymystä: (1) mihin sähkö oikeasti menee, (2) mitä syntyvälle lämmölle voidaan tehdä ja (3) miten tulokset osoitetaan mitattuna ja vertailukelpoisesti, ei lupauksina. 
Ilmasto ja isompi kuva:
Ilmastovaikutus pienenee vain, jos toimet näkyvät mitatuissa luvuissa. Periaate: mittaa ensin, paranna sitten, väitä vasta lopuksi.
Neuvo: vaadi aina rajaukset ja mittausjakso, kun joku kertoo “tehokkuudesta” tai “100 % puhtaasta sähköstä”. Väärinkäsitys: “yksi hyvä temppu” ratkaisee, yleensä ratkaisee päätösten ketju. 
2. Energiankulutus datakeskuksissa
Ymmärrät energian “kokonaiskuvan” datakeskuksessa.
Teho vs. energia (nopea muistisääntö): teho (kW, MW) kertoo hetkellisen kulutuksen tason, energia (kWh, MWh) kertoo kulutuksen kertymän ajassa. Esimerkiksi 10 kW jatkuva kuorma vuorokauden ajan on 240 kWh.
Datakeskuksen sähkönkulutus jakautuu kahteen pääosaan:
IT‑energia: palvelimet, tallennus ja verkkolaitteet (se osa, joka tuottaa itse palvelun).
Tukijärjestelmät: jäähdytys ja ilmavirrat, sähkönsyöttö ja ‑jakelu (UPS, muuntajat) sekä muut kiinteistön järjestelmät. Lähes kaikki käytetty sähkö päätyy lopulta lämmöksi, joten datakeskus on samalla myös jatkuva lämmönlähde. 
Ilmasto ja isompi kuva:
Sähkönkulutus muuttuu lähes kokonaan lämmöksi, siksi jäähdytys ja lämpö ratkaisevat paljon. Periaate: minimoi “IT:n ulkopuolinen” kulutus ja hyödynnä lämpö, jos voit.
Neuvo: aloita aina kahdesta mittauksesta: IT‑kulutus ja kokonaiskulutus (silloin näet myös tukikulutuksen). Väärinkäsitys: “jäähdytys on aina suurin osa”, se riippuu kohteesta ja suunnittelusta. 
Lisätieto (mittari): PUE  
PUE (Power Usage Effectiveness) on yleisin tunnusluku, jolla kuvataan datakeskuksen kokonaisenergiankulutuksen suhdetta IT‑laitteiden energiankulutukseen: mitä lähempänä PUE on arvoa 1, sitä pienempi osuus energiasta kuluu IT:n ulkopuolisiin tukijärjestelmiin. 
Ilmasto ja isompi kuva:
PUE kertoo, kuinka paljon “pakollista taustakulutusta” datakeskuksessa on IT‑työn päälle. Periaate: pyri pienentämään taustakulutusta, mutta pidä palvelutaso ja laiteturvallisuus kunnossa.
Neuvo: älä vertaile PUE‑lukuja ilman mittausjaksoa ja rajausta. Väärinkäsitys: “pieni PUE = automaattisesti pieni hiilijalanjälki”, sähkön tuotantotapa ratkaisee myös. 
3. Energian uudelleenkäyttö datakeskuksissa
Ymmärrät, mitä hukkalämmön hyötykäyttö tarkoittaa.
Datakeskukset tuottavat lämpöä väistämättä. Jos lämpö vain puhalletaan ulos, hukataan mahdollisuus parantaa energian kokonaishyödyntämistä. Suomessa hukkalämmön hyödyntäminen on usein tavallista realistisempaa, koska lämmitystarve on pitkä ja kaukolämpöverkkoja on paljon, mutta toteutus riippuu aina paikallisista reunaehdoista (ostaja, etäisyys, liityntä ja lämpötilatasot). 
Ilmasto ja isompi kuva:
Sama sähkö tuottaa sekä digipalvelun että lämpöä, lämpö voi korvata energiantarvetta muualla. Periaate: hyödynnä lämpö siellä missä se oikeasti syrjäyttää päästöjä.
Neuvo: selvitä lämmön ostaja ja liityntä jo suunnittelussa, ei jälkikäteen. Väärinkäsitys: “hukkalämmön hyödyntäminen on aina ilmastoteko”, vaikutus riippuu siitä, mitä lämmöllä korvataan ja paljonko lisäenergiaa tarvitaan. 
Käytännössä lämpö kerätään jäähdytyksen kautta ja nostetaan lämpöpumpuilla hyötykäyttöön sopivaan lämpötilaan. 
Ilmasto ja isompi kuva:
Lämpöpumppu “nostaa” matalalämpöisen hukkalämmön käyttökelpoiseksi. Periaate: minimoi lisäsähkö (hyvä hyötysuhde) ja maksimoi korvattava poltto‑ tai tuotantomuoto.
Neuvo: kysy aina: paljonko lämpöä toimitetaan (MWh) ja mikä osa vuodesta (mittausjakso). Väärinkäsitys: “prosenttiluku yksin riittää”, oleellista on todellinen datakeskuksen ulkopuolelle hyötykäyttöön toimitettu energia ja sen vaikutus. 
Lisätieto (mittari): ERF  
Energian uudelleenkäytön osuutta voidaan kuvata tunnusluvulla ERF (Energy Reuse Factor), joka kertoo, kuinka suuri osa datakeskuksen kuluttamasta energiasta toimitetaan hyötykäyttöön datakeskuksen rajojen ulkopuolelle. 
Ilmasto ja isompi kuva:
ERF tekee lämpöhyödyn näkyväksi yhdenmukaisella tavalla. Periaate: raportoi vain se energia, joka oikeasti käytetään muualla (ei “teoreettista potentiaalia”).
Neuvo: pyydä ERF:n lisäksi selitys, mihin lämpö menee ja miten se mitataan. Väärinkäsitys: “ERF kertoo kaiken ilmastovaikutuksesta”, se kertoo uudelleenkäytön osuuden, ei sähkön päästöjä. 
4. Datakeskuksen energiatehokkuuden parantaminen (jäähdytys, käyttöaste, virtualisointi)
Energiatehokkuus datakeskuksessa tarkoittaa: sama palvelu, vähemmän kilowattitunteja. Energiatehokkuuden parantaminen on jatkuvaa työtä, joka koskee sekä IT‑puolta (kuorma ja laitteet) että infrastruktuuria (jäähdytys ja sähkönsyöttö). 
Ilmasto ja isompi kuva:
Jokainen säästetty kWh pienentää päästöjä heti, riippumatta siitä mistä sähkö tulee. Periaate: vähennä “turhia kilowattitunteja” ennen kuin ostat lisää “vihreää sähköä”.
Neuvo: etsi ensin jatkuvat peruskulut (24/7), koska niistä syntyy suurin vuosivaikutus. Väärinkäsitys: “tehokkuus on vain tekniikkaa”, usein se on käyttöä, mitoitusta ja kurinalaista operointia. 
IT‑puolella suurin perusperiaate on välttää vajaakäyntiä ja ylimitoitusta. Kuormaa kannattaa tiivistää pienemmälle määrälle palvelimia (virtualisointi/ kontit), sammuttaa tai lepuuttaa aidosti tarpeettomat resurssit ja varmistaa, että kapasiteetti seuraa kysyntää. Tämä tuottaa usein “ilmaisimmat säästöt”, koska se vähentää sekä IT‑kulutusta että jäähdytyksen tarvetta. 
Ilmasto ja isompi kuva:
Tyhjäkäyvä palvelin kuluttaa ja lämmittää – vaikka käyttäjä ei hyödy. Periaate: pidä käyttöaste järkevänä ja poista “aina päällä” ‑kapasiteetti.
Neuvo: tee säännöllinen “siivous”: löydä vajaakäyttöiset palvelimet ja päätä: mihin ne yhdistetään tai milloin ne sammutetaan. Väärinkäsitys: “varmuuden vuoksi enemmän rautaa”? Usein parempi varmuus tulee hyvistä varmistuksista ja automaatiosta, ei jatkuvasta ylikapasiteetista. 
Jäähdytyksessä tärkeintä on vähentää turhaa jäähdytystyötä. Yksinkertaiset ratkaisut kuten kuuma‑ ja kylmäkäytävien erottelu, ilmavirtojen ohjaus ja “vapaajäähdytys” silloin kun olosuhteet sallivat, pienentävät usein energiankulutusta. Tehotiheissä palvelimissa ja kuormissa (esim. paljon GPU‑laskentaa) nestejäähdytys voi olla perusteltu, koska lämpö saadaan pois tehokkaammin, mutta kokonaisratkaisu ratkaisee. 
Ilmasto ja isompi kuva:
Jäähdytys ei ole “lisäosa”, vaan osa koko energiabudjettia. Periaate: jäähdytä vain sen verran kuin on pakko ja juuri sieltä missä on pakko.
Neuvo: tarkista lämpötila‑asetukset ja ilmavirrat mittaamalla, älä oletuksilla. Väärinkäsitys: “kylmempi on aina turvallisempi”, liian kylmä voi olla turhaa kulutusta, ja suositukset riippuvat laitteista. 
Sähkönsyötössä ja varmistuksissa (UPS, varavoima) tarkoitus on luotettavuus, mutta myös mitoitus vaikuttaa häviöihin. Ylisuuri varmistus voi nostaa häviöitä ja pitää yllä turhaa peruskuormaa. Siksi energiatehokas toteutus on usein “oikein mitoitettu toteutus”: riittävä toimintavarmuus ilman jatkuvaa ylimääräkulutusta. 
Ilmasto ja isompi kuva:
Luotettavuus maksaa energiaa – mutta fiksu mitoitus maksaa vähemmän. Periaate: suunnittele varmistukset riskin mukaan, älä rutiinin mukaan.
Neuvo: jos et pysty perustelemaan varmistustason tarvetta, et todennäköisesti tarvitse sitä. Väärinkäsitys: “paras on aina maksimi”, joskus se on vain kallein ja päästöintensiivisin. 
5. Uusiutuvien energialähteiden hyödyntäminen
Ymmärrät, miten sähkön tuotantotapa vaikuttaa datakeskuksen käytönaikaisiin päästöihin.
Datakeskuksen käytönaikaiset päästöt syntyvät pääosin sähköstä: mitä enemmän sähköä ja mitä hiilipitoisempaa tuotantoa, sitä suurempi ilmastovaikutus. Siksi kaksi isoa vipua ovat (1) kulutuksen pienentäminen ja (2) vähähiilinen/hiilivapaa sähkö. 
Ilmasto ja isompi kuva:
Sama kWh voi olla ilmastolle “kevyt” tai “raskas” riippuen tuotannosta. Periaate: vähennä kWh ja puhdista kWh.
Neuvo: pyydä toimittajalta sekä kulutus (kWh) että päästökerroin/selitys sähköstä, ilman näitä et tiedä vaikutusta. Väärinkäsitys: “uusiutuva = automaattisesti hiilineutraali kaikissa merkityksissä”, väitteeseen liittyy rajauksia ja todentamista. 
Uusiutuvaa tai vähähiilistä sähköä hankitaan käytännössä kolmella tavalla: (1) oma tuotanto (yleensä vain osa tarpeesta), (2) pitkäaikaiset hankintasopimukset (PPA) ja (3) alkuperän todentaminen (esim. alkuperätakuu). Kun näet väitteen “100 % uusiutuvaa”, kysy aina mihin se perustuu ja mitä se kattaa (koko kulutus vai osa, ja onko kyse vuositasosta vai aidosti ajallisesti vastaavasta tuotannosta). IEA korostaa, että pelkkä vuositasoinen “100 %” uusiutuvan ostaminen sertifikaateilla ei välttämättä tarkoita, että käyttöhetkellä sähkön tuotanto on uusiutuvaa samassa verkossa. 
Ilmasto ja isompi kuva:
“100 % uusiutuvaa” voi tarkoittaa eri asioita – ja siksi se voi myös johtaa harhaan. Periaate: tee väitteistä läpinäkyviä: mitä ostettiin, mistä ja mille ajalle.
Neuvo: pyydä lyhyt “selite”: oma tuotanto / PPA / alkuperätakuu + maantieteellinen alue + mittausjakso. Väärinkäsitys: “sertifikaatti yksin takaa päästöjen laskun”, päästövaikutus riippuu myös sähköjärjestelmästä ja lisäisyydestä. 
Lisätieto (mittari): REF  
Uusiutuvan energian osuutta kuvataan usein tunnusluvulla REF (Renewable Energy Factor), jolle on määritelty laskenta- ja raportointitapa. 
Ilmasto ja isompi kuva:
REF kertoo uusiutuvan energian osuuden, ei suoraan hiilijalanjälkeä. Periaate: käytä REF:iä läpinäkyvyyteen, mutta arvioi päästöt erikseen.
Neuvo: jos vertailet toimittajia, pyydä REF:n lisäksi selitys päästökertoimista ja rajauksista. Väärinkäsitys: “korkea REF = aina pieni CO₂”, verkon päästökerroin ja kulutuksen määrä ratkaisevat silti. 
6. Hiilijalanjäljen seuranta ja hallinta
Ymmärrät, mistä datakeskuksen hiilijalanjälki muodostuu ja mitä luvuista pitää tarkistaa.
Datakeskuksen päästöt voi jäsentää kahteen koriin: (1) käytönaikaiset päästöt (sähkönkulutus ja sen tuotanto) ja (2) elinkaaripäästöt (rakentaminen, laitteiden valmistus, kuljetus, huolto ja elinkaaren loppu). Käytössä päästölogiikka on yksinkertainen: kulutetut kilowattitunnit × sähkön päästöintensiteetti. 
Ilmasto ja isompi kuva:
Päästöt “syntyvät kahdessa ajassa”: osa syntyy nyt käytössä, osa syntyi jo hankinnoissa. Periaate: vähennä yhtä aikaa käyttöä ja turhia hankintoja.
Neuvo: pidennä laitteiden käyttöikää ja vältä ennenaikaisia laitevaihtoja, jos suorituskyky ja energiatehokkuus eivät oikeasti parane kokonaisuutena. Väärinkäsitys: “uusi laite on aina vihreämpi”, joskus paras teko on käyttää hyvin sitä, mikä jo on. 
Päästöjen pienentämisessä on kaksi käytännön päävipua:
energiatehokkuus (vähemmän kWh samaan palveluun) ja
vähähiilinen/hiilivapaa sähkö (pienempi päästökerroin).  
Jos kompensaatioita käytetään, ne on syytä erottaa selvästi päästöjen vähentämisestä: kompensointi ei korvaa tehokkuutta eikä puhdasta sähköä, vaan on korkeintaan erillinen lisätoimi. 
Ilmasto ja isompi kuva:
Ilmasto ei “näe” sertifikaattipuhetta, se näkee tonnit ja kilowattitunnit. Periaate: tee ensin suorat vähennykset, vasta sitten pohdi kompensointia.
Neuvo: pyydä toimittajalta päästölukujen yhteyteen aina rajaus (mitä mukana) ja kerroin (millä laskettu). Väärinkäsitys: “hiilineutraali” tarkoittaa nollapäästöä, usein se tarkoittaa nollaa vasta laskennan ja kompensaation jälkeen. 
7. Mitattavasti vähäpäästöisen datakeskuksen peruselementit ja periaatteet
EU:ssa datakeskuksilta edellytetään yhä enemmän läpinäkyvyyttä. Komission delegoitu asetus (EU) 2024/1364 velvoittaa raportoimaan tietoja EU‑tietokantaan datakeskuksista, joiden asennettu IT‑tehontarve on vähintään 500 kW, ja määrittää raportoitavia tunnuslukuja sekä yhteisiä laskentaperiaatteita.
Ilmasto ja isompi kuva:
Läpinäkyvyys pakottaa erottamaan todellisen parannuksen viestinnästä. Periaate: rakenna mittaus ja raportointi “sisään”, se on tuleva perusvaatimus.
Neuvo: jos suunnittelet datakeskusta tai hankit palvelua, varmista että mittauspisteet ja datan laatu ovat kunnossa alusta asti. Väärinkäsitys: “raportointi on paperityötä”, se on myös johtamisen työkalu. 
Mittaaminen mahdollistaa vähäpäästöisyyden tunnistamisen: ilman mittaamista “vähäpäästöinen” jää helposti mielikuvaksi. Siksi vertailussa tärkeintä ei ole vain itse lukema, vaan myös mittausjakso ja rajaus: mitä on laskettu mukaan ja miltä ajalta. 
Ilmasto ja isompi kuva:
Sama palvelu voi näyttää “vihreältä” eri tavalla, jos rajaus muuttuu. Periaate: vertaa vain vertailukelpoisia lukuja (sama rajaus, sama ajanjakso).
Neuvo: pyydä aina “kolmen kysymyksen paketti”: mittausjakso, rajaukset ja laskentatapa. Väärinkäsitys: “yksi numero kertoo kaiken”, ilman taustatietoa ei tiedetä mittausjaksoa, rajauksia eikä laskentatapaa. 
EU:n perusmittarit (PUE, WUE, ERF, REF) on hyvä runko: PUE kertoo energiatehokkuudesta, WUE veden käytön tehokkuudesta, ERF energian uudelleenkäytön osuudesta ja REF uusiutuvan energian osuudesta. 
Ilmasto ja isompi kuva:
Mittarit tekevät ympäristöpuheesta todennettavaa. Periaate: käytä relevantteja mittareita ja vaadi niiden taustatiedot.
Neuvo: hankinnoissa pyydä vähintään PUE, WUE, ERF, REF + rajaus + mittausjakso. Väärinkäsitys: “sertifikaatti riittää”, sertifikaatti ilman mitattuja arvoja on liian helppo kiertotie. 
8. Parhaat käytännöt ympäristösuorituskykyisen datakeskuksen toteuttamisessa
Ympäristösuorituskyky ei synny yhdestä asiasta, vaan päätösten ketjuna. Suurimmat vaikutukset syntyvät usein jo ennen ensimmäistäkään laitetta: sijainti, sähköliityntä, laajennettavuus, jäähdytysratkaisut ja se, löytyykö hukkalämmölle järkevä hyödyntäjä. 
Ilmasto ja isompi kuva:
Sijainti lukitsee energian, veden ja lämmön reunaehdot vuosiksi. Periaate: valitse paikka, jossa puhdas sähkö ja lämpömarkkina ovat realistisia.
Neuvo: tee “kolmen verkon tarkistus”: sähköverkko, lämpöverkko, vesitilanne. Väärinkäsitys: “sijainti on vain tonttihinta”, se on myös päästöbudjetti. 
Suunnittelussa modulaarisuus on usein ilmastoteko: kun kapasiteettia voi kasvattaa vaiheittain, vältetään vuosien vajaakäyttö. Käytännössä tämä tarkoittaa, että tilaa ja infraa ei rakenneta “kaikkea heti valmiiksi”, jos kuorma kasvaa vasta myöhemmin. 
Ilmasto ja isompi kuva:
Ylimitoitus kuluttaa energiaa ja sitoo turhaan myös rakennus- ja laitepäästöjä. Periaate: rakenna kasvun mukaan, ei arvauksen mukaan.
Neuvo: aseta käyttöasteelle tavoite ja tee päätösrajat: milloin lisätään räkkejä, milloin ei. Väärinkäsitys: “ylikapasiteetti on turvallisuutta”, usein se on vain kallista ja päästöintensiivistä tyhjäkäyntiä.Jäähdytyksessä perusajatus on tehdä vain tarvittava työ: hyödynnä vapaajäähdytystä kun olosuhteet sallivat, ohjaa ilmavirtoja mittausten perusteella ja pidä asetukset laitevalmistajien suositusalueilla. Tehotiheissä kuormissa valitse jäähdytys sen mukaan, mikä oikeasti toimii tehokkaasti kokonaisuutena (ei vain “uusi tekniikka” ‑periaattella). 
Ilmasto ja isompi kuva:
Jäähdytys voi olla suuri “piilokuluttaja”, jos ilmavirrat ovat huonosti hallitut. Periaate: ohjaa, erota, mittaa.
Neuvo: varmista kuuma/kylmä‑erottelu ja tiivisteet ennen kuin ostat lisää jäähdytystehoa. Väärinkäsitys: “lisää jäähdytystä ratkaisee”, usein ongelma on ilman reitti, ei teho. 
Sähkönsyötössä ja varmistuksissa hyvä käytäntö on riskiperusteisuus: varavoima ja UPS ovat pakollisia, mutta niiden mitoitus ja käyttö (esim. testauskäytännöt) vaikuttavat sekä luotettavuuteen että turhiin häviöihin. Tee varmistuksesta “riittävä ja perusteltu”, älä “maksimaalinen oletuksena”. 
Ilmasto ja isompi kuva:
Jokainen lisävarmistus tuo lisää laitteita, häviöitä ja valmistuspäästöjä. Periaate: mitoita varmistus palvelun kriittisyyden mukaan.
Neuvo: dokumentoi varmistustaso ja sen perustelu (Service Level Agreement/riskit) jo tarjousvaiheessa. Väärinkäsitys: “kaikille sama varmistus”, kriittisyys vaihtelee. 
Sähkön hankinnassa paras käytäntö on läpinäkyvyys: jos viestit “100 %”, kerro aina mihin se perustuu (oma tuotanto/PPA/alkuperä) ja mitä se kattaa (koko kulutus vai osa, ja mille ajalle). Lisäksi kuorman jousto (jos mahdollista) voi tukea sähköjärjestelmää, mutta vain jos palvelutaso ei kärsi. 
Ilmasto ja isompi kuva:
Sähköjärjestelmä on yhteinen, datakeskus voi olla myös joustava kuorma. Periaate: tee sähköstä todennettavaa ja pyri vähentämään “piikkikulutusta”.
Neuvo: jos jousto on mahdollista, määritä etukäteen mitkä kuormat voivat “liikkua” ja mitkä eivät. Väärinkäsitys: “joustaminen sopii kaikille”, kaikille palveluille se ei sovi. 
Hukkalämmössä parhaat käytännöt alkavat reunaehdoista: onko lämmölle ostaja, onko liityntä järkevä, ja onko lämpötilataso hyödynnettävissä kohtuullisella lisäsähköllä. Vedenkäytössä paras käytäntö on tehdä kulutus näkyväksi ja valita ratkaisut, jotka ovat paikallisesti kestävät. 
Ilmasto ja isompi kuva:
Hukkalämpö ja vesi ovat paikallisia resursseja – sama ratkaisu ei toimi kaikkialla. Periaate: minimoi paikallinen haitta ja maksimoi paikallinen hyöty.
Neuvo: vaadi WUE‑tyyppinen veden seuranta, jos jäähdytys käyttää vettä. Väärinkäsitys: “vesi on sivuseikka pohjoisessa” – vesiriskit ja lupaehtojen tiukentuminen voivat koskea myös täällä. 
Operoinnin sääntö, “mittaa–optimoi–dokumentoi”: seuraa kulutusta riittävän tarkasti, reagoi poikkeamiin, ja pidä muutoshistoria kunnossa, jotta parannus on todennettavissa. Näin vältät tilanteen, jossa “parannus” onkin vain laskentatavan muutos. 
Ilmasto ja isompi kuva:
Ilmastovaikutus pienenee vain, jos muutos toteutuu käytännössä joka päivä. Periaate: tee jatkuvasta parantamisesta rutiini, ei projekti.
Neuvo: nimeä omistaja jokaiselle pääkuluerälle (IT, jäähdytys, sähköketju, vesi). Väärinkäsitys: “optimointi tehdään kerran”, datakeskus elää koko ajan. 
9. Yritysten esimerkkejä, saavutetut hyödyt ja opit
Esimerkit näyttävät saman asian kuin teoria: tulokset syntyvät paikallisista olosuhteista (sähkö, lämpöverkko, kumppanit) ja ne kannattaa esittää mitattuna, jotta ne ovat vertailukelpoisia. 
Ilmasto ja isompi kuva:
“Hyvä tarina” ei vielä tarkoita hyvää vaikutusta, mittaus tekee siitä totta. Periaate: suosi ratkaisuja, joilla on todennettavat luvut.
Neuvo: pyydä esimerkkien yhteyteen aina “mitä mitattiin ja miltä ajalta”. Väärinkäsitys: “esimerkkikohde = yleispätevä malli”, paikalliset reunaehdot ratkaisevat. 
Google Hamina: Google on kertonut käynnistävänsä ensimmäisen Off Site‑lämmöntalteenottoprojektinsa Haminassa, ja Haminan Energian mukaan hukkalämpö voisi kattaa noin 80 % paikallisen kaukolämpöverkon vuotuisesta lämmöntarpeesta; Google on myös kuvannut kohteen toimivan korkealla “carbon‑free energy” ‑tasolla omassa raportoinnissaan. 
Ilmasto ja isompi kuva:
Datakeskus voi muuttua paikalliseksi lämmöntuottajaksi, jos kaukolämpöverkko ja kumppani ovat valmiina. Periaate: rakenna yhteistyö energiayhtiön kanssa aikaisin.
Neuvo: kysy: kuka omistaa lämpöpumpun, kuka mittaa toimitetun lämmön, ja mihin lämpö menee. Väärinkäsitys: “lämmön hyödyntäminen on aina helppo lisä”, se on usein erillinen investointi ja sopimuspaketti. 
CSC LUMI Kajaanissa: CSC on kuvannut, että hukkalämpö kattaa noin 20 % Kajaanin kaukolämmöstä ja että lämmön hyödyntämisellä on sekä ilmasto- että kustannusvaikutuksia. 
Ilmasto ja isompi kuva:
Suuri laskentakapasiteetti voi olla energiajärjestelmälle plussa, jos lämpö saadaan käyttöön. Periaate: tee hukkalämmöstä suunnittelun reunaehto, ei “bonus”.
Neuvo: varmista liityntä ja lämpömarkkina jo tontti- ja sähköpäätösten yhteydessä. Väärinkäsitys: “lämpö voidaan aina myydä”, joskus ostajaa ei ole tai etäisyys tappaa kannattavuuden. 
Helsingin seutu: Helen ja Telia ovat kasvattaneet datakeskuksen hukkalämmön hyödyntämistä kaukolämmössä, ja Elisa kertoo hyödyntävänsä datakeskustensa hukkalämpöä Espoon ja Helsingin lämmityksessä. 
Ilmasto ja isompi kuva:
Kun kaukolämpöverkko on lähellä, lämpö voidaan muuttaa päästövähennyksiksi nopeammin. Periaate: suosi sijainteja, joissa hukkalämmölle on valmis “reititys”.
Neuvo: kysy aina: kuinka paljon lämpöä menee verkkoon vuodessa (MWh), ei vain “montako asuntoa se lämmittää”. Väärinkäsitys: “asuntojen määrien mukaan kerrottu hyöty on tarkka”, se on usein havainnollistava arvio, ei mittaustulos. 
10. Tulevaisuuden suuntaukset ja käytännön ohjenuora
Datakeskusten tulevaisuuden iso ajuri on tehotiheyden kasvu: AI‑kuormat ja kiihdyttimet (GPU) lisäävät sähkönkulutusta ja lämpöä per laite, mikä nostaa jäähdytyksen ja sähkön saatavuuden suunnittelun ytimeen. IEA korostaa, että digitalisaation ja AI:n kasvulla on suora kytkentä sähköjärjestelmään: “ei ole AI:ta ilman energiaa”. 
Ilmasto ja isompi kuva:
Tehontarve kasvaa, ja silloin pienetkin tehokkuuserot muuttuvat isoiksi päästöeroiksi. Periaate: tee tehokkuudesta ja puhtaasta sähköstä “kynnyskriteeri”, ei lisäbonus.
Neuvo: kun lasket kasvua, muista myös jäähdytys ja infra, pelkkä IT‑MW ei ole koko kuva. Väärinkäsitys: “pilvi hoitaa tämän”, datakeskus on pilvipalvelut ovat palvelimia datakeskuksissa. 
Läpinäkyvyysvaatimukset kiristyvät, ja samalla nousee esiin elinkaari: kun sähköntuotantoverkot puhdistuvat, laitteiden ja rakennuksen “sisäänrakennetut” päästöt korostuvat enemmän. Siksi käyttöiän pidentäminen, modulaarisuus ja kierrätys ovat nousussa yhtä paljon kuin energiatehokkuus. 
Ilmasto ja isompi kuva:
“Hintalappu” ei ole vain sähkölasku, se on myös materiaalipäästöjä. Periaate: pidennä käyttöikää ja vältä turhaa vaihtamista.
Neuvo: tee hankintoihin vaatimus uudelleenkäytöstä/kierrätyksestä ja elinkaaren hallinnasta. Väärinkäsitys: “kiertotalous on pehmeä arvo”, se on kovaa päästömatematiikkaa. 
Yksi käytännön ohjenuora, joka ei vanhene: suunnittele ensin, mittaa oikein, paranna suurimmat kuluerät ja vältä “100 %” ‑tyyppiset väitteet ilman selitystä. Kun vaikutus näkyy mitatuissa tunnusluvuissa ja rajaukset ovat selkeät, se näkyy myös ilmastossa. 
Ilmasto ja isompi kuva:
Ilmasto hyötyy vain todennetuista muutoksista, ei tavoitteista. Periaate: tee päätöksiä, jotka kestävät auditoinnin.
Neuvo: pidä “todentamisen tarkastuslista” aina mukana (rajaukset, mittausjakso, menetelmä). Väärinkäsitys: “tulevaisuus ratkaisee tekniikalla”, perusfysiikka ei muutu: sähkö → lämpö. 
11. Resurssit ja lisämateriaali
Kirjat ja raportit  
– IEA: Data Centres & Data Transmission Networks (yleiskuva energiasta ja päästöistä).   
– IEA: Energy and AI (AI:n ja datakeskusten kytkentä sähköjärjestelmään). citeturn4search2turn4search1  
– EU JRC: EU Code of Conduct – Best Practice Guidelines (konkreettiset energiatehokkuuden parhaat käytännöt). citeturn8search2turn8search14
EU-sääntely ja raportointi  
– Komission delegoitu asetus (EU) 2024/1364 (raportoitavat tiedot ja yhteiset KPI:t). citeturn7search10turn7search12
Mittarit (määritelmät)  
– PUE: ISO/IEC 30134‑2. citeturn8search0turn8search4  
– WUE: ISO/IEC 30134‑9. citeturn8search1  
– ERF: ISO/IEC 30134‑6. citeturn4search3  
– REF: ISO/IEC 30134‑3. citeturn2search2
12. Tenttikysymyksiä ja harjoitustehtävät, arvioi omaa osaamistasi ja kehityskohteita
Tenttikysymyksiä (10 kysymystä)
Mitä datakeskus tekee, ja miksi sen “tuote” on palvelu? (Vihje: luku 1)
Mihin kahteen pääosaan datakeskuksen energiankulutus jakautuu, ja miksi tämä jako on tärkeä? (Vihje: luvut 1–2)
Selitä teho (kW) ja energia (kWh) ja laske: 10 kW kuorma 24 h = ? kWh. (Vihje: luku 2)
Mikä tekee hukkalämmön hyödyntämisestä Suomessa usein realistista, ja mitkä reunaehdot ratkaisevat toteutettavuuden? (Vihje: luku 3)
Nimeä kolme käytännön vipua, joilla datakeskuksen energiatehokkuutta parannetaan. (Vihje: luku 4)
Mitä “100 % uusiutuvaa” -väite voi käytännössä tarkoittaa, ja mitä tarkistat ennen kuin pidät väitettä vertailukelpoisena? (Vihje: luku 5)
Mitä eroa on käytönaikaisilla päästöillä ja elinkaaripäästöillä, ja miten käytönaikaiset päästöt arvioidaan perusperiaatteella? (Vihje: luku 6)
Miksi rajaukset ja mittausjakso ovat välttämättömiä, jotta “vähäpäästöisyys” on vertailukelpoinen väite? (Vihje: luku 7)
Selitä yhdellä lauseella, mitä kukin perusmittareista kuvaa (PUE, WUE, ERF, REF). (Vihje: luku 7)
Mikä on yksi päätös, joka pitää tehdä jo ennen rakentamista, jos haluat hyödyntää hukkalämpöä? (Vihje: luku 8)
Tenttikysymyksiä (10 kysymystä)
Miksi “vihreä datakeskus” on epäselvä ilmaus ilman määritelmää, ja miten määrittelisit “vihreyden” mitattavasti? (Vihje: luvut 1 ja 7)
Mitkä ovat neljä perusmittaria, joihin ympäristösuorituskyky kannattaa ankkuroida? (Vihje: luku 7)
Mitä tarkoitetaan mittausjaksolla ja rajauksilla, ja miksi ne ovat yhtä tärkeitä kuin itse mittariarvo? (Vihje: luku 7)
Saat toimittajalta PUE-arvon. Mitkä kolme tarkennusta pyydät ennen kuin vertaat sitä toiseen toimittajaan? (Vihje: luvut 2 ja 7)
Saat väitteen “100 % uusiutuvaa sähköä”. Mitkä kaksi kysymystä kysyt aina? (Vihje: luku 5)
Mikä ero on “uusiutuvalla”, “vähähiilisellä/hiilivapaalla” ja “hiilineutraalilla”, ja miksi kompensaatio pitää käsitellä erikseen? (Vihje: luvut 5–6)
Toimittaja kertoo hyödyntävänsä hukkalämpöä. Mitkä kolme reunaehtoa ratkaisevat toteutettavuuden? (Vihje: luku 3)
Toimittaja antaa päästöintensiteetin (esim. gCO₂e/kWh). Mitkä kaksi tietoa pitää nähdä, jotta luku on vertailukelpoinen? (Vihje: luku 6)
Miksi pelkkä sertifikaatti ei riitä vertailuun, ja mitä tietoja pyydät sen lisäksi? (Vihje: luku 7)
Tee “uskottavuustarkistus” yhdellä lauseella: mitkä kolme tietoa pitää löytyä, jotta ympäristöväite on vertailukelpoinen? (Vihje: luku 7)
