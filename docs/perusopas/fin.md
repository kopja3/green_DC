# P4 Datakeskuksen elinkaaren vaiheet

## Tavoite

Kuvata datakeskuksen elinkaari esiselvityksestä suunnitteluun, rakentamiseen, käyttöönottoon, käyttöön, modernisointiin ja lopulta käytöstä poistoon niin, että vihreä ICT -näkökulma energia, päästöt, vesi, materiaalit ja raportointi on mukana jokaisessa vaiheessa.

## Luku kattaa

- Elinkaaren vaiheet ja niiden päätöspisteet – mitä päätetään missäkin vaiheessa
- Vastuut ja dokumentointi – kuka tuottaa mitkä tiedot ja milloin
- Energia-, data- ja materiaalivirrat elinkaaren aikana – mitä syntyy, mitä mitataan, mitä siirretään eteenpäin
- Modernisointi ja kapasiteetin muutokset – laajennukset, supistukset ja niiden vaikutus tehokkuuteen
- Käytöstä poisto – tietoturvallinen purku, laitekierto ja materiaalien kiertäminen

## Tuotokset – dokumentoitavat päätökset

- Elinkaarsuunnitelma: vaiheet, aikataulu, riippuvuudet
- Rooli- ja vastuumatriisi: suunnittelu–rakentaminen–operointi–raportointi
- Modernisointipolku: päivityssyklit, kapasiteetin kasvu/supistus, vaikutus mittareihin
- Käytöstä poisto- ja kierrätyssuunnitelma: datahävitys, materiaalivirrat, toimittajaketju
- Luvun lopussa lähteet ja viittaukset

---

## P4.1 Esiselvitys ja tavoitteiden asettaminen

Elinkaaren ensimmäinen vaihe on esiselvitys, jossa määritellään datakeskushankkeen peruslähtkohdat: datakeskuksen rooli, tehtävä ja tavoitteet. Tässä vaiheessa arvioidaan esimerkiksi:

- Mitä liiketoiminnallista tai yhteiskunnallista tarvetta datakeskus palvelee? Onko kyse teknologisesta tarpeesta, kasvavasta kapasiteetin kysynnästä vai esimerkiksi kansallisesta turvallisuudesta?
- Kuinka paljon laskentatehoa, tallennuskapasiteettia ja verkkokapasiteettia tarvitaan? Tämä johdetaan palveluiden kysynnästä ja kasvuprojektioista.
- Mikä on palveluiden tavoiteltu käytettävyystaso ja suorituskyky? Esimerkiksi onko tavoitteena 99,99 % käytettävyys (SLA) tai tietty maksimiviive käyttäjille.

Nämä vaatimukset vaikuttavat suoraan varmistusratkaisuihin ja kapasiteettivarauksiin[1].

Vihreän datakeskuksen kannalta esiselvityksessä on olennaista asettaa myös ympäristö- ja energiatehokkuustavoitteet. Näitä voivat olla esimerkiksi:

- **Tavoiteltu PUE-taso**: esimerkiksi PUE 1,3 tietyn ajan kuluessa käyttönotosta
- **Hyvä maksimipäästötaso CO₂-ekvivalentteina**: per palveluyksikkö, eli hiilijalanjälkitavoite, johon pyritään sähköhankinnan ja tehokkuuden kautta
- **Uusiutuvan energian osuus**: esimerkiksi 80 % uusiutuvaa energiaa sähkökulutuksesta
- **Tavoitteet vedenkäytölle (WUE) ja hukkalämmön hyödyntämiselle (ERF)**, mikäli ne ovat hankkeen kannalta relevantteja

Esiselvityksen lopputuloksena syntyy kokonaiskuva tarpeista ja tavoitteista. Sen pohjalta organisaation johto voi päättää, miten hankkeessa edetään: rakennetaanko oma datakeskus, käytetään kumppanin konesalia vai turvaudutaan pilvipalveluihin, vai yhdistetään näitä. Päätös voi olla esimerkiksi aloittaa omalla pienemmällä konesalilla ja skaalata pilvessä, tai päinvastoin[2].

---

## P4.2 Suunnitteluvaihe

Suunnitteluvaiheessa esiselvityksen tavoitteet muutetaan konkreettisiksi ratkaisuiksi. Kytännössä tässä vaiheessa:

**Valitaan toteutusmalli ja kumppanit**: Päätetään, toteutetaanko hanke DBO-mallilla vai perinteisemmin jaetaanko vastuita eri toimijoille. Kilpailutetaan ja valitaan avaintoimittajat: rakennusurakoitsija, sähkö- ja jäähdytysjärjestelmätoimittajat, automaatiojärjestelmätoimittajat jne.

**Määritellään perusratkaisut**: Määritellään rakennuksen koko ja rakenne, sähkönkäytön arkkitehtuuri (kuinka monta muuntajaa, millainen UPS-ratkaisu), jäähdytysjärjestelmän tyyppi (esimerkiksi vapaajäähdytys, veden vs. ilman käyttö), hukkalämmön talteenottokonsepti sekä automaatio- ja valvontajärjestelmien laajuus.

**Tehdään tilavaraukset tulevaisuutta varten**: Suunnittelupöydällä on helpompi huomioida mahdolliset tulevat teknologiat. Esimerkiksi varataan tila aurinkopaneeleille katolle, varataan putkitukset hukkalämpöliitännölle, tai suunnitellaan generaattorikenttä siten, että biopolttoainesiiloille on tilaa, jos sellaisiin vaihdetaan myöhemmin.

Suunnittelussa on ehdottoman tärkeä noudattaa sekä määräyksiä että standardeja. Vihreän datakeskuksen kohdalla tämä tarkoittaa:

- Ympäristö- ja rakennusmäärysten täyttämistä
- Suunnitelmat käydään läpi viranomaisten kanssa: ympäristöluvat, melunsuojaus, jätehuoltosuunnitelmat
- Mahdolliset YVA (ympäristövaikutusten arviointi) -prosessit otetaan huomioon suurissa hankkeissa
- Tietoturva- ja tietosuojasääntelyn huomioimista
- Ympäristösertifikaattien vaatimuksien huomioimista, mikäli tavoitteena on hakea esimerkiksi LEED- tai BREEAM-sertifiointia

Dokumentoimalla esiselvityksessä kaikki keskeiset vaatimukset ja tavoitteet, varmistetaan, että seuraaviin vaiheisiin lähdetään olemassa projektin peruskirjan kanssa vihreinä tavoitteineen[1][3].

---

## P4.3 Rakentaminen

Rakentamisvaiheessa suunnitelmat muuttuvat fyysiseksi todellisuudeksi. Vihreän datakeskuksen rakentamisessa korostuvat laadunvarmistus ja ympäristötietoisuus työmaalla. Keskeiset huomioitavat asiat ovat:

**Maanrakennus ja perustukset**: Tontin valmistelu, kaapelikanavien ja putkitusten teko sekä perustusten valaminen. Tässä vaiheessa pyritään minimoimaan ympäristölle aiheutuva häiriö: pöly, melu, veden valuminen ja kierrätetään kaivuumassoja. Esimerkiksi ylijäämä-ainesta voidaan hyödyntää maisemoinnissa paikan päällä.

**Rakennuksen runko ja vaippa**: Posin teräs- ja betonirakenteiden pystytys. Vihreän rakentamisen hengessä suositaan vähähiilistä betonilaatuja ja kierrätysterästä mahdollisuuksien mukaan. Rakenteiden tiiveys (ilmavuodot) ja eristys vaikuttavat suoraan energiankulutukseen myöhemmin, joten niihin kiinnitetään erityistä huomiota.

**Sähkö- ja jäähdytysjärjestelmien asennus**: Tämä kattaa muuntajat, UPS-laitteet, sähköjakelukeskukset, varavoimageneraattorit, jäähdytyskoneet, pumput, putkistot ja ilmastointikoneet. Asennusten aikana laadunvarmistus on tärkeä: huolimattomasti asennettu eristys tai väärin kalibroitu anturi voi myöhemmin heikentää energiatehokkuutta tai luotettavuutta. Ympäristön kannalta varmistetaan myös, että esimerkiksi jäähdytysjärjestelmän kylmainekäsittely tehdään asianmukaisesti ilman päästöjä.

**Kaapelointi ja tietoliikenne**: Palvelinsalin kaapeloinnit (sähkö ja data) sekä automaatio- ja valvontajärjestelmien kytkennät suoritetaan. Selkeä kaapelointi- ja merkintäjärjestys varmistaa, että ilma pääsee kiertämään esteetösti laitekaapeissa, auttaa jäähdytystä ja mahdollistaa myöhemmin laajennukset tai muutokset ilman turhaa ylimitoitusta[4].

Rakentamisvaiheessa on syytä pitää mielessä ympäristötavoitteet: jätteiden lajittelu työmaalla, rakentamisen aikaisten päästöjen minimointi (esimerkiksi rajoitetaan dieselkoneiden käyttö, käytetään mahdollisuuksien mukaan sähköistä kalustoa) ja lähialueen häiriiden minimointi ovat tärkeitä. Tämä luo projektista vihreän kuvan jo ennen valmistumista ja usein edesauttaa sertifiointien saamista.

Projektin johto varmistaa, että dokumentaatio pysyy ajan tasalla: kaikki asennetut laitteet, niiden tekniset tiedot ja asetukset kirjataan huolella. Tämä dokumentaatio on kullanarvoista operointivaiheessa, kun pyritään säätämään ja optimoimaan järjestelmiä[2].

---

## P4.4 Käyttöönotto

Käyttöönottovaiheessa varmistetaan, että datakeskus toimii suunnitellulla tavalla ennen täysimittaista tuotantokyyttä. Tämä sisältää:

**Järjestelmien testaaminen**: Jokainen keskeinen järjestelmä testataan läpi. Sähköjärjestelmän osalta tehdään esimerkiksi syttökatkotest: simuloidaan sähkökatko ja varmistetaan, että UPS ja generaattorit käynnistyvät odotetusti. Jäähdytysjärjestelmä testataan sekä osakuormalla että täydellä kuormalla: varmistetaan, että asetetut lämpötilarajat pitävät ja hälytykset toimivat. Automaatio- ja valvontajärjestelmien testit varmistavat, että sensorit toimivat oikein ja että etäohjaus toimii[1].

**Kuormitustestit**: Ennen oikean tuotantokuorman tuomista voidaan käyttää keinotekoista kuormaa (lämpökuormia tai testipalvelimia) simuloimaan täyttä IT-kuormitusta. Näin nähdään, miten datakeskus käyttäytyy tostilanteessa: nousevatko jotkin lämpötilat liikaa, muodostuuko odottamattomia pullonkauloja ilmankierrossa, pitääkö PUE tavoitellulla tasolla. Samalla voidaan kalibroida mittalaitteet: varmistetaan, että PDU-iden mittaukset vastaavat päämitta rivejä.

**Turvallisuustestit**: Fyysisen turvallisuuden testaus (kulunvalvonta, kamerajärjestelmät, murtovariytyshälytykset) ja paloturvallisuustestit (paloilmoittimet, kaasusammutusjärjestelmät, savunpoisto) ovat kriittisiä ennen kuin tuotantodata tuodaan sisään. Myös kyberturvallisuuden perusasiat varmistetaan: hallintaverkot suojattu, etäyhteydet testattu, kaikki oletussalasanat vaihdettu.

**Ensimmäiset mittaukset**: Käyttönoton aikana käynnistetään mittaristo ja otetaan ensimmäiset referenssilukemat keskeisille tunnusluvuille. Esimerkiksi mitataan datakeskuksen hetkellinen PUE koekuormalla, jotta saadaan lähttaso myöhempää seurantaa varten. Samoin kirjataan muistiin verkon viiveet ja läpäisykykytestien tulokset sekä varmistetaan, että ne ovat vaaditulla tasolla[2].

Käyttönotosta huipentuu usein hyväksymistarkastukseen, jossa projekti muodollisesti siirtyy rakentajilta operointitiimille. Tällöin varmistetaan, että kaikki suunnitellut toiminnot on toteutettu ja tavoitteet saavutettu. Vihreille tavoitteille tässä kohtaa tarkastetaan esimerkiksi, saavutettiinko tavoiteltu PUE testissä ja ovatko uusiutuvan energian ratkaisut valmiina käyttöön. Mahdolliset poikkeamat kirjataan ja korjaussuunnitelmat laaditaan.

---

## P4.5 Käyttö, operointi ja ylläpito

Käyttö- eli operointivaihe on datakeskuksen elinkaaren pisin ja jatkuvin vaihe. Sen aikana varmistetaan päivittäin, että:

- **Palvelut ovat käyttäjille saatavilla** sovitun palvelutason (SLA) mukaisesti. Tämä tarkoittaa jatkuvaa valvontaa: esimerkiksi palveluiden vasteaikoja, järjestelmien kuormitusta ja kapasiteetin riittävyyttä seurataan. Mikäli jokin osa infrastruktuurista vikaantuu, varmistusmekanismit (redundanttiset laitteet, varayhteydet) astuvat voimaan ja korjaavat toimenpiteet aloitetaan viipymättä[5].

- **Energiankulutus ja ympäristömittarit seurataan säännöllisesti**. Esimerkiksi PUE lasketaan jokaiselta päivältä/viikolta/kuukaudelta ja analysoidaan, onko trendi toivottu. Samoin seurataan jatkuvasti:
  - Hiilidioksidipäästöjen kehitystä (CUE)
  - Jos sähkötuotannon päästökerroin vaihtelee, hukkalämmön hyödyntämisasteita
  - Vedenkulutusta (WUE)
  
  Nämä luvut kootaan selkeiksi raporteiksi[1][3].

- **Ennakoiva huolto ja laitteiden kunnonvalvonta** ehkäisevät häiriöitä. Koneoppimista käyttävät mallit ja sensoridata voivat kertoa esimerkiksi kohoavasta lämpötilasta jossain laakerissa tai heikentyvästä akuston kapasiteetista jo ennen vikaa. Huoltotaukoja suunnitellaan niin, että ne vaikuttavat palveluihin mahdollisimman vähän[2].

- **Vihreän operoinnin periaatteisiin kuuluu**, että laitteita ei vaihdeta turhaan uuteen (jolloin syntyy elektroniikkarosua), vaan pyritään käyttämään koko suunniteltu elinkaari, kuitenkin niin, ettei vikaantumisriski kasva kohtuuttomasti.

- **Dokumentaatio ja varautumissuunnitelmat** pidetään ajan tasalla. Operointivaiheessa tapahtuu muutoksia: esimerkiksi uusia laitteita lisätään, asiakaskapasiteettia muutetaan. Nämä on dokumentoitava, jotta järjestelmien tilaa ymmärretään kokonaan[6].

---

## P4.6 Modernisointi ja kapasiteetin laajennus

Modernisointi on olennainen osa vihreän datakeskuksen elinkaaria. Teknologia ei seiso paikallaan, ja kilpailukyky sekä ympäristövaikutukset edellyttävät päivityksiä. Modulaarinen arkkitehtuuri – mikäli se on alusta asti ollut käytössä – helpottaa modernisointia:

- Voidaan esimerkiksi vaihtaa yksi UPS-moduuli kerrallaan uudempaan ilman koko järjestelmän alasajoa
- Tai rakentaa uusi jäähdytyskonetta ja kytkeä se rinnalle ennen vanhan poistoa
- Palvelinpopulaatiota voidaan vaihtaa osissa: uudet, tehokkaammat palvelimet voidaan asentaa rinnalle ja kuormia siirtää asteittain

Tämä kyky uudistua osissa on vihreän datakeskuksen elinehto[2].

Operoinnin näkökulmasta modernisointi on myös oppimisprosessi: uudet laitteet tuovat uudet parametrit ja joskus uudet mittarit. Siksi modernisointiin yhdistetään yleensä koulutusta henkilöstölle ja päivityksiä dokumentaatioon ja prosesseihin[5].

Kapasiteetin laajennus tai supistus vaikuttaa mittareihin. Esimerkiksi:
- Uuden IT-kapasiteetin lisääminen voi aluksi heikentää PUE-lukua, kunnes kuormitus saavuttaa optimaalisen tason
- Energiatehokkaitten laitteiden asennus parantaa PUE:tä
- Hukkalämmön hyödyntämisen laajentaminen parantaa ERF-arvoa

Näiden muutosten dokumentointi on tärkeää mittareiden tulkinnalle myöhemmin[1].

---

## P4.7 Purku ja elinkaaren loppu – kiertotalous

Elinkaaren viimeisessä vaiheessa datakeskus tai sen osa puretaan käytöstä. Vihreän datakeskuksen näkökulmasta purku ei ole pelkästään hankkeen loppu, vaan myös mahdollisuus hyödyntää sen materiaaleja ja infrastruktuuria uudelleen.

**Rakennusmateriaalien kierrätys**: Purkamisessa syntyy runsaasti metalliromua (teräsrungot, kaapelit), betonia, elektroniikkaa ja sekalaista jätettä. Vihreän tavoitteena on lajitella ja ohjata mahdollisimman suuri osa näistä materiaalivirroista uudelleenkäyttöön tai kierrätykseen:

- Teräs ja metallit menevät metallinkiertoon
- Betoni murskattaan ja käytetään täyteaineena
- Käyttökelpoiset laitetilat (kontit tms.) voidaan ehkä myydä tai siirtää muualle[2]

**Elektroniikkaromu (SER)**: Palvelimet, tallennuslaitteet, UPS-it, PDU-t, akut – kaikki sisältävät komponentteja, jotka on käsiteltävä sähkö- ja elektroniikkaromua koskevien säädösten mukaisesti. Kytännössä erikoistuneet kierrätysfirmat purkavat laitteet, erottelevat metallit (kupari, alumiini, jalometallit) piirilevyistä ja hävittävät haitalliset aineet (lyijyakut, kondensaattorit, jäähdytysnesteet) ympäristöturvallisesti[3].

**Vaaralliset aineet**: Datakeskuksissa on joitakin aineita, jotka vaativat erityiskäsittelyn purussa:
- Jäähdytyskoneiden kylmaineet on talteenottava asianmukaisesti (ne voivat olla otsoniikerrosta tuhoavia tai kasvihuonekaasuja)
- UPS-akujen elektrolyytti on ongelmarosua
- Dieselgeneraattoreissa voi olla polttoainejäämiä, jotka tulee poistaa huolellisesti[4]

**Tontin jatkokäyttö**: Kun datakeskus puretaan, syntyy usein hyvin varusteltu teollisuustontti. Siellä voi olla esimerkiksi edelleen voimassa oleva suurjänniteverkkon liittymä tai kaukolämpöliitännät, jotka voidaan hyödyntää uudessa käytössä. Vihreän periaatteen mukaista onkin pyrkiä löytämään tontille uusi elämä – mieluiten niin, että aiempi infrastruktuuri hyödynnetään. Esimerkiksi entiseen datakeskukseen voisi sijoittaa sähköasemaa, akuvarastoa tai muuta toimintaa, joka hyötyy olemassa olevista liitännöistä[2].

**Kiertotalouden tavoite**: Hyvin suunniteltu vihreä datakeskus huomioi purkamisen jo alusta materiaalivalinnoissa: suositaan ratkaisuja, jotka ovat helposti eroteltavissa. Esimerkiksi jos seinäpaneelit on pultattu (eikä valutettu kiinteästi), ne voi purkaa ja mahdollisesti käyttää muualla. Samoin laitekaapeilla standardikoosta voidaan myydä eteenpäin.

Purkuvaiheessa onnistuminen mitataan pitkälti siinä, kuinka pieni jätemäärä loppusijoitukseen päätyy. Vihreän tavoitteena on mahdollisimman lähellä nolla-jätettä: lähes kaikki purettu joko uudelleenkäyttöön tai kierrätyksen. Näin datakeskuksen koko elinkaaren hiilijalanjälki pienenee, kun materiaalipanoksia ei hukata[2][5].

---

## P4.8 Kestävä ja modulaarinen suunnittelu läpi elinkaaren

Kaiken kaikkiaan kestävä datakeskus ei synny yksittäisistä ratkaisuista, vaan kokonaisvaltaisesta elinkaariajattelusta. Suunnittelussa on alusta asti mietittävä datakeskuksen purkamista ja materiaalien kiertoa: näin vältetään suunnittelemasta sellaista, mikä 10–15 vuoden päästä koituisi ongelmarosueeksi[6].

**Modulaarisuus** lävitsee kaikki vaiheet:
- Esiselvityksessä määritellään modulaariset kapasiteettitavoitteet
- Suunnittelussa valitaan modulaariset laitekokonaisuudet
- Rakentamisessa toteutetaan modulaarisesti: kontit, standardikomponentit
- Operoinnissa hyödynnetään modulaarisuutta optimoinnissa: osien päälle–pois kytkeminen
- Modernisoinnissa vaihdetaan moduuli kerrallaan
- Purussa moduulit puretaan ja lajitellaan tehokkaasti

Modulaarisuus estää ylimitoitusta ja helpottaa päivityksiä, mikä on sekä taloudellisesti että ekologisesti järkevää[2].

**Pitkäjänteisyys** on toinen läpileikkaava periaate. Jo esiselvityksessä ajatellaan datakeskuksen roolia 10–15 vuoden päässä. Suunnittelussa mietitään, miten keskus skaalautuu ja vastaa tuleviin standardeihin. Operoinnissa luodaan kulttuuri, jossa jatkuva parantaminen on normi. Modernisoinnissa investoidaan tulevaisuuden teknologiaan, jos se pitkällä tähtimellä säästää energiaa ja päästöjä. Ja purkuvaiheessa ajatellaan seuraavaa elinkaaraa niille materiaaleille ja komponenteille, jotka vapautuvat[3].

Näin datakeskuksen elinkaari saadaan hallituksi siten, että palveluiden kehittyessä ja laajentuessa myös ympäristökuormitus pysyy mahdollisimman pienenä. Vihreän datakeskuksen elinkaariajattelu onkin lähellä sukua elinkaariajattelulle (Life Cycle Thinking) laajemminkin kestävän kehityksen yhteydessä: huomioidaan hankkeen vaikutukset ja mahdollisuudet jokaisessa vaiheessa ja tehdään päätöksiä, jotka optimoivat kokonaisuutta eikä vain yksittäistä kohtaa[4][6].

---

## P4.9 Tulevaisuuteen varautuminen ja pitkän aikavlin suunnittelu

Tulevaisuuteen varautuminen on olennainen osa vihreän datakeskuksen elinkaarisuunnittelua. Jo hankkeen alkuvaiheessa pyritään ennakoimaan, millaisia vaatimuksia ja muutoksia tulevaisuus voi tuoda tullessaan:

**Skaalautuvuus**: Datakeskus suunnitellaan siten, että sen kapasiteettia voidaan laajentaa tai tarvittaessa supistaa kustannustehokkaasti. Tämä voi tarkoittaa esimerkiksi varattua tilaa lisäräkeille, ylimitoitettuja pääkaapeleita ja putkituksia tulevia laajennuksia varten tai modulaarisia rakennusosia, jotka voidaan liittää olemassa olevaan rakenteeseen. Skaalautuvuus koskee myös jäähdytystä ja sähköjärjestelmiä: ne suunnitellaan modulaarisiksi, jolloin lisäämällä moduuleja kapasiteetti kasvaa ilman koko järjestelmän uusimista[1][5].

**Teknologian kehittyminen**: Varaudutaan siihen, että uudet teknologiat voivat mullistaa nykyiset ratkaisut. Esimerkiksi jäähdytyksessä voi yleistyä suorajäähdytys piirille (direct-to-chip cooling) tai täysin uudet kylmaineet, energian varastoinnissa akkujen energiatiheys voi moninkertaistua, tai IT-puolella kvanttilaskenta tms. voi tuoda uudenlaisia tilantarpeita. Suunnittelussa tämä tarkoittaa jousta: tilojen muuntojoustavuutta, ylikapasiteetin välttämistä ja standardien seuraamista, jotta uusia innovaatioita voi ottaa käyttöön[2].

**Huollettavuus ja päivitettävyys**: Laitteet valitaan ja sijoitetaan niin, että niiden huolto ja vaihto on vaivatonta. Esimerkiksi jos yhden palvelimen vaihto vaatii neljän muun irrottamisen edestä, se on huonoa suunnittelua. Vihreä näkökulma korostaa myös, että helppo huollettavuus pidentää laitteiden elinikää: komponentit voidaan vaihtaa ilman, että koko laite hylätään. Sama pätee infrakomponentteihin: modulaariset UPS-it, vaihdettavat jäähdytysyksiköt jne.[4].

**Sääntelyn muutokset**: Ympäristö- ja energiatehokkuusvaatimukset todennäköisesti tiukentuvat ajan mittaan. EU ja kansalliset hallinnot voivat asettaa uusia rajoja esimerkiksi datakeskusten energiatehokkuudelle tai pakollisia uusiutuvan energian osuuksia. Hyvä pitkän aikavälin suunnitelma seuraa sääntelytrendejä ja varmistaa, että datakeskus on joko jo valmiiksi edellä vaatimuksia tai ainakin muokattavissa niitä vastaavaksi. Esimerkiksi mittarointijärjestelmä rakennetaan riittävän kattavasti, jotta mikä tahansa tuleva raportointivaatimus – olipa se sitten hiilijalanjälki, energiatehokkuus tai vaikka vedenkulutus – saadaan siitä ulos[3][5].

Lopulta hyvin suunniteltu vihreä datakeskus on pitkän aikavälin infrastruktuuri, joka mukautuu teknologian, sääntelyn ja liiketoiminnan muutoksiin kestävästi. Se ei ole staattinen investointi, vaan elävä kokonaisuus, jota ohjataan ja kehitetään jatkuvasti asetettujen tavoitteiden puitteissa. Tämä jatkuvuus ja muutoskyky yhdistettynä vahvaan ympäristövastuuseen varmistavat, että datakeskus pysyy sekä hyödyllisen että vihreän koko elinkaaren ajan[2][6].

---

## P4 Yhteenveto

Datakeskuksen elinkaarita voidaan tarkastella useista näkökulmista, mutta vihreän näkökulman kannalta on olennaista huomioida jokaisen vaiheen – esiselvityksestä purkuun – ympäristövaikutukset ja mahdollisuudet. Elinkaariajattelulla varmistetaan, että hankkeen kokonaisvaikutus optimoidaan, eikä vain yksittäisiä välivaiheita parandeta. Modulaarisuus, pitkäjänteisyys ja kiertotalouden periaatteet luovat perustan, jonka varassa datakeskus voi toimia kestvällä tavalla nyt ja tulevaisuudessa.

---

## P4 Lähdeviitteet

[1] Green Data Centers: A Survey, Perspectives, and Future Directions. Jin, X., Zhang, F., Vasilakos, A. V., Liu, Z. (2016). arXiv:1608.00687.

[2] Data Center Handbook. Geng, H. (Ed.). (2015). John Wiley & Sons.

[3] The ICT sector, climate and the environment – Interim report. LVM. (2020). Publications of the Ministry of Transport and Communications 2020/14. Ministry of Transport and Communications, Finland.

[4] Information technology – Data centre facilities and infrastructures – Part 4: Key performance indicators. EN 50600-4. CENELEC. European Committee for Electrotechnical Standardization.

[5] Sustainability-aware Resource Provisioning in Data Centers. Wang, J., Palanisamy, B., Xu, J. (2020). In 2020 IEEE 6th International Conference on Collaboration and Internet Computing (CIC), pp. 60–67. IEEE. https://doi.org/10.1109/CIC50333.2020.00018

[6] Achieving Sustainability in Computing by Minimizing Data Center Carbon Footprints. Sabree, R. M. S. (2025). Journal of Information Processing and Management.

---

# P5 Datakeskuksen toiminta vaiheittain

## Tavoite

Kuvata, miten datakeskuksen palvelut toimitetaan käytäntöön: mihin perustuva kuormien ja palvelutasojen kuvaus, kuinka kapasiteetti suunnitellaan, miten IT-teho vaihtelee ajan funktiona, sekä kuinka nämä vaatimukset johtavat sähkö-, jähdy tys- ja varmistusjärjestelmien mitoitukseen. Luku kytkee IT-puolen vaatimukset infrastruktuurin ratkaisuihin tehomitoitusketjun kautta.

## Luku kattaa

- Kuormille ja palvelutasoille perustuva mitoituslähtödata
- Kapasiteettisuunnittelu: aktiivinen ja varalla pidettävä kapasiteetti
- IT-tehon ajallinen vaihtelu ja sen huomiointi infrastruktuurin mitoituksessa
- Sähkönkäyttö ja -jakelu verkosta palvelinkaappiin: liittymä, muuntajat, UPS, jakokeskukset, PDU-yksiköt
- Varmistusperiaatteet ja redundanssi (N, N+1, 2N)
- Jäähdytystarpeen määrittäminen IT-tehon perusteella

## Tuotokset – dokumentoitavat päätökset

- Tykuorman ja palvelutason määritys: SLA, SLO ja niistä johdettu mitoituslähtötieto
- Kapasiteettisuunnitelma: Cinst, Cactt, Cres ja niiden dokumentointi
- IT-tehoprofiilin kuvaus: PITt(t), huipputeho ja sen kesto
- Sähköjärjestelmän mitoitus: liittymäteho, muuntajien koot, UPS-kapasiteetti, generaattorikoko
- Varmistusperiaatteen dokumentointi ja sen vaikutus kapasiteetin mitoitukseen
- Jäähdytystarve ja lmpkuorman määritys
- Perustuu P1.4:n tehomitoitusketjun symboleille ja käsitteille

---

## P5.1 IT-kuormien ja palvelutasojen määritys mitoituksen lähtökohtana

Datakeskuksen tehomitoitus alkaa selkeällä kuvauksella siitä, mitä työtä datakeskus tekee ja minkä palvelutason tavoite siihen liittyy. Käytännössä tämä tarkoittaa:

**IT-tykuorman (Lt) kuvaus**: Mitä sovelluksia ja palveluja datakeskus ajetaan? Mikä on palvelupyyntöjen määrä ajan funktiona? Tunnetaanko kuorman päivittäinen tai kausivaihtelut? Esimerkiksi:

- E-kauppapalvelussa kuormituspiikki voi tulla iltoihin tai joululomalla
- Tilastointitapauksessa kuormitus voi olla tasaista
- Tutkimuslaskennassa on pitkiä, intensiivisiä ajoja jotka vaativat huippukapasiteetin[1]

Kuormaa voidaan mallintaa useilla tavoilla: perinteisen kapasiteettisuunnittelun lähestymistavassa käytetään historiallista dataa ja klusterointia kuormityypiksi, joille sitten tehdään ennusteet[2].

**Palvelutasovaatimukset (SLA/SLO)**: Missä palvelutasossa asiakkaat ja liiketoiminta ovat? Tyypillisiä tavoitteita ovat:

- Saatavuus: 99,9 % tai 99,99 % – kuinka paljon alasaikaa vuodessa sallitaan?
- Vasteaika: p50, p95, p99 – mikä on hyväksyttävä kunkin pyynnön käsittelyaika?
- Palautumistavoitteet (RTO – Recovery Time Objective, RPO – Recovery Point Objective) kriittisissä palveluissa

Nämä vaatimukset määrittävät suoraan, kuinka paljon kapasiteettia pidetään "varalla" häiriö- ja kuormahuipputilanteita varten[1][3].

---

## P5.2 Sähkönkäyttö ja -jakelu verkosta palvelinkaappiin

Sähkönjakelun arkkitehtuuri on keskeinen osa tehomitoitusta, koska jokainen vaihe ketjussa tuo hviitä ja vaatii mitoitusta.

**Shkliittymä**: Datakeskus liittyy kantaverkkoon tai jakeluverkkoon. Liittymäteho päätetään IT-kuormasta johdetun mitoitustehon perusteella, joihin lisätään kaikki infrastruktuurihvit. Esimerkiksi:

- IT-teho: 1,0 MW
- Shkjakelun ja UPS-hvit (~15 %): +0,15 MW
- Jhdytyksen shkteho (~0,8–1,5 MW per IT-MW, riippuen jhdytyskeinosta): +1,2 MW
- Yhteensä liittymäteho: ~2,35 MW

Liittymäkokouksissa sopiva kapasiteetti on tyypillisesti määritelty 10–20 vuoden kuormitusprognoosin perusteella, ja liittymä suunnitellaan modulaarisesti: esimerkiksi 2×10 MW tai 3×6,67 MW redundanssin varmistamiseksi[2][4].

**Muuntajat**: Päämuuntajat muuttavat kantaverkon jännitteen sopivaksi datakeskuksen sisäiselle käytölle. Vihreän datakeskuksen kannalta muuntajavalinnat vaikuttavat tehokkuuteen: nykuaikaiset pienihäviömuuntajat (yleensä öljy- tai kaasueristeisiä) voivat vähentää muuntopiirin hviitä merkittävästi. Muuntajien mitoitus tehdään huipputehovaatimuksen perusteella, mutta ne usein ylimitoitetaan jonkin verran, jotta tulevaisuuden laajennuksille on varaa[1][2].

**Pääkeskus**: Pääkeskus sisältää kytkimet ja suojalaitteet. Se jakaa sähkön UPS-järjestelmille (kriittiset kuormat) ja tarvittaessa suoraan tukijärjestelmille, jotka eivät tarvitse sähkökatkoksilta suojausta (esimerkiksi toimistotilat, valaistus). Pääkeskus dokumentoidaan huolellisesti ja merkitään selkeästi turvallisuuden ja myöhemmän ylläpidon vuoksi[3].

**UPS-järjestelmät (Uninterruptible Power Supply)**: UPS:n tehtävä on toimia puskurina sähkökatkon ja varavoimageneraattorin käynnistymisen välissä – tyypillisesti 10–30 sekuntia. Nykyään UPS-järjestelmät ovat usein modulaarisia, jolloin yhden moduulin vikaiontua muut pystyvät jatkamaan palvelun toimittamista. UPS-kapasiteetti (kW ja energia kWh) määräytyy kriittisten kuormien perusteella ja annetuista palvelutasovaatimuksista[2][4].

**Varavoima**: Varavoima (yleensä diesel- tai kaasukäyttöiset generaattorit) käynnistyy, kun sähkökatko kestää pidempään kuin UPS-akut. Generaattorin kapasiteetti mitoitetaan koko datakeskuksen maksimikuorman perusteella, mukaan lukien UPS-järjestelmien uudelleenlataus. Vihreän datakeskuksen näkökulmasta varavoimalla on merkittävä hiilijalanjälki: fossiilisen polttoaineen käyttö ja testikäyttöjen päästöt. Uusina vaihto ehtoina tutkitaan biokaasu-, vety- ja akkuperustaisia ratkaisuja, jotka voivat vähentää päästöjä merkittävästi[2][5].

**Jakeluverkko (jakokeskukset ja PDU-yksiköt)**: Sähkön jakel jatkuu UPS:ltä jakokeskusten ja PDU-yksiköiden kautta palvelinkaappeihin. Jakokeskukset jaetaan sali-alueille ja PDU Power Distribution Unit -yksiköt huolehtivat yksittäisten rkkien sähköityksestä. Vihreässä datakeskuksessa PDU-yksiköt on usein varustettu pienillä mittareilla, joilla seurataan jokaisen rkin virrankulutusta reaaliajassa. Näin saadaan tarkkaa dataa laitekuormista, mikä auttaa löytämään alikytetyt (ja silti sähköä kuluttavat) laitteet ja kohdistamaan optimointitoimet oikein[1][3].

---

## P5.3 Kapasiteettisuunnittelu: aktiivinen ja varalla pidettävä kapasiteetti

Kapasiteettisuunnittelun ydin on päätös siitä, kuinka paljon IT-resursseista pidetään aktiivisesti käytössä (Cactt) ja kuinka paljon varataan kuormahuippujen, ennusteen epävarmuuden ja vikatilanteiden varalle (Cres).

**Asennettu kapasiteetti (Cinst)**: Tämä on hankittu ja asennettu kokonaisresurssiylijyyppi – teoreettinen maksimi. Esimerkiksi 1 000 palvelinta tai 100 teratavua tallennuskapasiteettia.

**Aktiivinen kapasiteetti (Cactt)**: Se osa asennetusta kapasiteetista, joka pidetään käytössä ajanhetkellä t. Voidaan esimerkiksi olla 600 palvelinta käytössä ja 400 varalla.

**Varakapasiteetti (Cres)**: Kapasiteetti, joka pidetään käytettävissä kuormahuippujen, ennusteen epävarmuuden ja vikatilanteiden varalta. Varakapasiteetin suuruus määrä tyy palvelutasovaatimuksista ja varmistusperiaatteista. Esimerkiksi:

- N-varmistus: mikään ei ole redundantti, kaikki resurssit käytössä, vikatilanteessa palvelu keskeytyy
- N+1-varmistus: yksi laite voi vioittua, ja palvelu jatkuu (ylimääräinen 1/N varakapasiteettia)
- 2N-varmistus: koko infrastruktuuri on kaksi kertaa (täysi redundanssi)

Vihreän datakeskuksen näkökulmasta kapasiteettisuunnittelu on kriittinen: liian suuri varakapasiteetti tarkoittaa paljon tyhjäkäynnillä toimivaa laitteistoa, mikä kuluttaa energiaa kuormasta riippumatta. Toisaalta liian pieni varakapasiteetti voi johtaa palvelun häiriöihin. Optimaalinen suunnittelu vaatii hyvää tuntemusta kuormista ja palvelutasotavoitteista[2][3][4].

---

## P5.4 IT-tehon ajallinen vaihtelu ja huipputeho

IT-teho (PITt) eli IT-laitteiden käyttämä sähköteho muuttuu ajan kuluessa, ja tämä vaihtelu määrittää infrastruktuurin mitoituksen.

**IT-tehoprofiilin muodostuminen**: Kun IT-kuormat vaihtelevat, myös sähkönkulutus vaihtelee:

- Korkealla kuormituksella (esim. 80 % resurssien käytöstä) palvelimet kuluttavat paljon energiaa
- Matalalla kuormituksella (esim. 20 % käytöstä) palvelimet kuluttavat vähemmän, mutta monissa tapauksissa eivät laskeverran eli "energiaproportionaalinen" tehokkuus ei ole täydellinen

Tällä on merkitys: perinteisten yritysdatasalien kyttaste on raportoitu usein noin 6–12 % tasolla, kun taas hyperscale-datasaleissa se on korkeampi, koska kuormia voidaan konsolidoida ja ohjata laajassa resurssipoolissa[2][5].

**Huipputeho (PITt,max)**: Sähkö- ja jäähdytysjärjestelmät mitoitetaan tyypillisesti huipputehon perusteella. Huipputeho määritetään:

- IT-tuotannon määrittelystä ja kasvuennusteista
- Palvelutasovaatimuksista (jos SLA vaatii 99,99 % saatavuutta, huippua ei saavuteta jokapäivä)
- Ajallisen vaihtelu tuntemisesta

Mitoitusteho yleensä sisältää varaa huippujen yläpuolelle varmennusperiaatteen vuoksi. Esimerkiksi jos arvioitu huipputeho on 1,0 MW ja varmistus on N+1 (20 % varakapasiteettia), mitoitetaan järjestelmät 1,2 MW:lle[2][3].

---

## P5.5 Jäähdytystarpeen määrittäminen

IT-laitteiden tuottama lmpenergia, joka on poistettava jäähdytysillä, määritetään IT-tehon perusteella:

**Lmpkuorma (Qtht)**: Lähes kaikki IT-laitteisiin syötetty sähköteho muuttuu lopulta lämpöenergiaksi. Muutamia prosentteja lukuun ottamatta pätee seuraava:

Qtht ≈ PITt + Phvit,muut

missä Phvit,muut sisältää muiden sähkölaitteiden hviit, joita voidaan arvioida noin 5–10 % IT-tehosta[1][3].

Jäähdytyskoneen eli jäähdytysjärjestelmän (esim. chiller) tulee poistaa täyt Qtht. Esimerkiksi:

- IT-teho 1,0 MW → Lmpkuorma noin 1,05 MW
- Jäähdytysjärjestelm mitoitetaan poistamaan 1,05 MW lämpöenergiaa

**Jäähdytyksen sähköteho (Pcoolt)**: Jäähdytyskoneen oma sähköteho riippuu jäähdytysmenetelmästä ja ulkoisista olosuhteista. Vapaa jäähdytys (free cooling) ilman ulkoilmaa käyttämällä on energiatehokas. Koneellinen jäähdytys (kompressionijäähdytys) on energiaintensiivisempi. Jäähdytystehon (kW) ja poistettavan lmpkuorman (kWth) suhde kuvataan useimmiten COP-luvulla (Coefficient of Performance) tai vastaavilla mittareilla[3][4].

Vihreän datakeskuksen nkkulmasta jäähdytysteho on usein merkittävä osa kokonaisenergankulutusta, erityisesti, jos vapaajäädytys ei ole mahdollista. Sijainnin valinnalla (esim. viileämpi ilmasto), jäähdytysmenetelmän valinnalla (hybrid, suorajäähdytys) ja hukkalämmön hyödyntämisellä voidaan vähentää jäähdytysenergian kulutusta merkitykseäsi[2][5].

---

## P5.6 Varmistusperiaatteet ja redundanssi mitoituksessa

Varmistusperiaatte määrittää, kuinka moninkertaisesti infrastruktuuri varmistetaan. Tämä näkyy sekä asennettavana infrastruktuurikapasiteettina että osakuormalla toimivien laitteiden hyötysuhtissa.

**N-varmistus**: Mikään komponentti ei ole redundantti. Yhden komponentin vika johtaa palvelun keskeytykseen. Mitoitus: minimimäärä laitteita kriittisten kuormien pyöritykseen.

**N+1-varmistus**: Yksi komponentti voi vioittua, ja palvelu jatkuu. Tyypillisesti merkitsee, että esimerkiksi UPS-järjestelmää tai generaattoria on kaksi (toinen aktiivinen, toinen varaalla), tai muuntajia on kaksi rinnakkain. Mitoitus: lisää noin 20 % kapasiteettia N:ään verrattuna.

**2N-varmistus**: Koko infrastruktuuri on kaksi kertaa. Esimerkiksi kaksi täysin erillstä sähköjakelua, kaksi jäähdytysjärjestelmää. Mitoitus: kaksinkertainen kapasiteetti. Käytetään usein kriittisimmissä palveluissa[2][3][4].

Varmistusperiaatteet näkyvät tehomitoituksessa:

- N + 1 -varmistus johtaa tyypillisesti siihen, että noin 50 % infrastruktuurikapasiteetista on varalla
- Tämä nostaa datakeskuksen kokonaisenergiankäyttöä, koska varakapasiteetin laitteet toimivat osittain tyhjäkäynnillä

Vihreän datakeskuksen suunnittelussa tasapainoillaan luotettavuuden ja energiatehokkuuden välillä: liian hireää varmistusta vältetään, mutta palvelutasotavoitteet täytetään[1][2].

---

## P5.7 Yhteenveto tehomitoituksesta IT:st infrastruktuuriin

Tehomitoitusketjun läpi mitoitus etenee IT-kuormista (Lt) ja palvelutasotavoitteista (SLA/SLO) lähtien ja johtaa lopulta infrastruktuurin mitoitukseen:

**IT-kuorma ja palvelutaso** → **Kapasiteettisuunnittelu** (Cinst, Cactt, Cres) → **IT-tehoprofiili** (PITt(t)) → **Sähkö- ja jäähdytysjärjestelmien mitoitus** (shkliittymä, muuntajat, UPS, generaattorit, jäähdytyskoneet)

Jokainen vaihe ketjussa tuo hviitä ja vaatii dokumentointia. Vihreässä datakeskuksessa kohteen on helppo jäljittää, mistä jokainen vaatimus tulee ja kuinka suuri vaikutus sillä on energiankulutukseen[1][2][3].

---

## P5 Lähdeviitteet

[1] Sustainability-aware Resource Provisioning in Data Centers. Wang, J., Palanisamy, B., Xu, J. (2020). In 2020 IEEE 6th International Conference on Collaboration and Internet Computing (CIC), pp. 60–67.

[2] The Datacenter as a Computer: An Introduction to the Design of Warehouse-Scale Machines. Barroso, L. A., Hlzle, U., Dean, J. (2018). Morgan & Claypool Publishers.

[3] Information technology – Data centre facilities and infrastructures – Part 4: Key performance indicators. EN 50600-4. CENELEC. European Committee for Electrotechnical Standardization.

[4] Data Center Handbook. Geng, H. (Ed.). (2015). John Wiley & Sons.

[5] United States Data Center Energy Usage Report. Shehabi, A., Smith, S. J., Sartor, D., Brown, R., Herrlin, M., et al. (2016). Lawrence Berkeley National Laboratory.

---

# P6 Energian kulutus ja uudelleenkäyttö

## Tavoite

Kuvata datakeskuksen energiankäytön jakautuminen eri komponenteille, tunnistaa energiansäästön potentiaalit, ja määrittää, miten hukkalämpö voidaan hyödyntää kestävällä tavalla. Luku kytketty mitoitukseen (P5) ja mittareihin (P7), sekä sijoittaa energian uudelleenkäytön osaksi vihreää kokonaisuutta.

## Luku kattaa

- Energian kulutusjakauma: IT-laitteet, sähkönjakelussa syntyviä hviitä, jäähdytys
- PUE-mittarin lähtötiedot ja sen rajoitteet
- Jäähdytyksen sähkötehokkuus: COP, DXOP ja muut lämpötilasta riippuvat tekijät
- Hukkalämmön talteenotto ja hyödyntäminen: teknologiat, rajapinnat, mittaus
- Kaukolämpöliityntöjen arkkitehtuuri ja toimivuus
- Vaativuuden minimisoinni infrastruktuurissa
- Mittausrajat ja energian jäljittäminen lähteestä käyttöön

## Tuotokset – dokumentoitavat päätökset

- Energian kulutusjakauman kartoitus: IT, jakeluhviit, jäähdytys, muut
- Tavoite PUE-taso ja keinot siihen pääsemiseksi
- Jäähdytykseen liittyvät tekniset ratkaisut ja COP-tavoitteet
- Hukkalämmän hyödyntmissuunnitelma: potentiaali, vastaanottaja, integraatio
- Mittausrajat ja energiaflujen dokumentointi
- Perustuu P1.8:n osa-alueisiin

---

## P6.1 Energian kulutusjakauma datakeskuksessa

Kokonaissähköenergia, joka datakeskus kuluttaa, jakaantuu useastaeri eri komponenttiin. Vihreän datakeskuksen näkökulmasta on tärkeä ymmärtää, mihin energia menee, jotta voidaan ohjata parannustoimia oikein.

**IT-laitteet**: Tämä on pääkomponentti – palvelimet, tallennus, verkko muodostavat ytimen. IT-laitteiden tehonkulutus riippuu:
- Laitteiden iästä ja malleista (uudet laitteet ovat tyypillisesti tehokkaampia)
- Kuormitusasteesta (korkealla kuormituksella teho on suurempi, mutta monissa tapauksissa laitteet eivät ole täysin energiapropor tionaalisia)
- Käytettyjen tekniikkoiden energiatehokkuudesta (CPU-arkkitehtuurit, muistien tehonkulutus jne.)

Tyypillisesti IT-laitteiden osuus kokonaiskulutuksesta on 40–60 % palvelinkeskuksessa, riippuen muista tekijöistä[1][2].

**Sähkönjakelussa syntyvät hviit**: Muuntajat, UPS-järjestelmät, johtojen resistanssi ja muut komponentit tuottavat hviitä. Nämä voivat olla 10–20 % IT-tehosta.
- Moderni muuntaja: ~1–2 % tehohvit
- UPS: ~5–10 % tehohvit kuormitusasteesta riippuen
- Kaapelointi ja kytkennät: ~2–3 %

Yhteensä sähkönjakelussa voi kadota 8–15 % energiasta[1][2].

**Jäähdytys**: Jäähdytysjärjestelmien (chillerit, pumput, puhaltimet, ilmastointikoneet) sähkönkulutus riippuu suuresti:
- Jäähdytysaineen valinnasta ja tekniikasta (kompressionijäähdytys vs. absorptiojäähdytys)
- Lämpötilaeroista (mitä suurempi ero, sitä enemmän energiaa tarvitaan)
- Ilmastoolosuhteista (vapaajäähdytys omalla ilmalla on energiatehokkuudessa ylivoimainen)
- Kaukolämmöstä käytettävä jäähdytys on usein vähemmän energiaintensiivistä

Jäähdytys voi kuluttaa 20–50 % kokonaisenergiasta, riippuen näistä tekijöistä[1][3].

**Muut kuormat**: Valaistus, toimistotilat, turvallisuusjärjestelmät, automaatio jne. voivat muodostaa 5–15 % kokonaiskulutuksesta.

Yhteensä: **Kokonaisenergia = IT-energia + Jakeluhviit + Jäähdytysenergia + Muut**

Vihreässä datakeskuksessa näiden eri osien energiansäästöpotentiaalit tunnistetaan ja priorisoidaan. Usein jäähdytys on suurin muuttujan olevan komponentin, ja juuri siellä voi saavuttaa merkittävimmät säästöt[2][4].

---

## P6.2 PUE-mittarin lähtötiedot ja käyttö

Power Usage Effectiveness (PUE) on eniten käytetty energiatehokkuusmittari datakeskuksissa. Se määritellään seuraavasti:

**PUE = Kokonaisenergia / IT-energia**

Esimerkiksi:
- Kokonaisenergia: 100 MWh kuukautta kohden
- IT-energia: 50 MWh kuukautta kohden
- PUE = 100 / 50 = 2,0

PUE 2,0 tarkoittaa, että jokaista IT-energian megawattituntia kohden kulutetaan 2 megawattituntia kokonaisenergiaa – toisin sanoen puolet energiasta menee IT:lle, puolet infrastruktuurihviille[1][3].

**PUE:n tulkinta**:
- PUE 1,0 (ihanteellinen): kaikki energia menee IT-laitteille, ei hviitä
- PUE 1,5 (hyvä): 67 % menee IT:lle, 33 % infrastruktuurihviille
- PUE 2,0 (keskimääräinen): puolet IT:lle, puolet hviille
- PUE > 2,5 (huono): alle 40 % IT:lle

Kansainvälisesti hyperscale-palveluntarjoajat raportoivat PUE-luvulla 1,1–1,3, kun taas pienempi, perinteisemmät datasallit jäävät usein 1,5–2,5 alueelle[1][2].

**PUE:n mittaus ja rajaus**: PUE:ta laskettaessa on määriteltävä selkeästi, mistä kokonaisenergia mitataan ja mistä IT-energia mitataan:

- **Kokonaisenergia**: Tyypillisesti sähkölaskutuspisteestä (meidän datakeskusta ruokkiva syöttö)
- **IT-energia**: PDU-mittauksista (Power Distribution Unit) – pistosta, joista energia menee palvelinkaappeihin

On kuitenkin huomattava, että PUE on hetkellinen mittari (kuvaa hetkellä tai keskiarvon aikavälin, esim. tunnin), eikä se ota huomioon:
- Kuormituksen ajallista vaihtelua
- Saatavuusvaatimuksia (redundanssi nostaa PUE:ta)
- Hukkalämmön hyödyntämistä (PUE-klassisella määritelmällä ei huomioida)

Näistä syistä PUE on hyödyllinen seurantamittari, mutta se pitää yhdistää muihin mittareihin, kuten CUE (Carbon) ja WUE (Water), sekä ERF (Energy Reuse), saadakseen kokonaisnäkemys vihreydestä[3][4].

---

## P6.3 Jäähdytyksen energiatehokkuus ja COP

Jäähdytyksen sähkötehokkuus on olennainen osa PUE-laskentaa ja merkityksellinen osa energian säästöpotentiaalista.

**COP (Coefficient of Performance)**: Kertoo, kuinka paljon lämpöenergiaa poistetaan suhteessa kulutettuun sähköenergiaan.

COP = Poistettava lämpöenergia (kWth) / Jäähdytyskoneen sähköteho (kWe)

Esimerkiksi:
- Poistettava lämpö: 1000 kWth (IT-kuorma + muut lähteet)
- Jäähdytyskoneen sähköteho: 200 kWe
- COP = 1000 / 200 = 5,0

COP 5,0 on erittäin hyvä. Perinteisessä kompressionijäähdytyksessä COP on tyypillisesti 3,0–4,5 normaaliolosuhteissa, ja se vaihtelee merkityksevästi ulkoilman lämpötilasta ja kosteudesta riippuen[1][2].

**COP:n riippuvuus olosuhteista**: 

- **Vapaajäähdytys (free cooling)**: COP > 10, kun ulkoilman olosuhteet ovat suotuisat (viileä ilma, sopiva kosteus). Tämä on merkityksellinen vihreän datakeskuksen näkökulmasta. Suomen kaltaisissa viileissä ilmastoissa vapaajäähdytys on käytettävissä merkittävän osan vuodesta, mikä parantaa kokonais-PUE:ta huomattavasti[1][3][5].

- **Hybridi-jäähdytys**: Yhdistää vapaajäähdytyksen ja koneellisen jäähdytyksen. Vapaajäähdytys käytetään, kun olosuhteet sallivat, muuten käynnistetään kompressionijäähdytys. COP voi olla 4–6 riippuen käyttöaikajakaaumasta[3].

- **Suorajäähdytys piirille (direct-to-chip)**: Uudempi tekniikka, jossa jäähdytysväliaine kytketään suoraan palvelimen prosessorin tai muiden komponenttien lähelle. Tämä parantaa lämmönsiirtoa, pienentää tarvittavaa jäähdytysenergiaa ja voi saavuttaa COP-arvot, jotka ovat jopa perinteisiä ratkaisuja parempia[2][4].

Vihreässä datakeskuksessa COP-tavoitteet asetetaan jo suunnitteluvaiheessa. Esimerkiksi tavoitteena voi olla keskimääräinen COP 4,5 vuodelle, mikä vaatii jäähdytysarkkitehtuurin huolellista valintaa ja paikallisten olosuhtheiden (ilmasto, vuodenajat) ymmärtämistä[1][3].

---

## P6.4 Hukkalämmön talteenotto ja hyödyntäminen

Datakeskuksissa tuotetaan runsaasti lämpöenergiaa, josta suurin osa menee nykyään hukkaan. Vihreät datakeskukset pyrkivät hyödyntämään tämän lämmön.

**Hukkalämmön potentiaali**: Kuten edellä todettiin, IT-laitteiden käyttämä energia muuttuu lähes kokonaan lämmöksi. Lisäksi jäähdytysjärjestelmät tuottavat omia lämpöjäänteitä. Yhteensä lähellä 100 % syötetystä energiasta on periaatteessa hyödyttävissä lämmön muodossa, vaikka käytännön puutteet ja kuljetus rajoittavat hyödyntämisastetta[1][3].

**Hukkalämmön kuljetus ja hyödyntäminen**:

Lämpöenergia voidaan kuljettaa:
- **Lämmönvaihdinten kautta kaukolämpöverkkoon**: Jos datakeskus sijaitsee kaukolmpverkon läheisyydes, jäähdytysvedet voidaan johtaa lämmönvaihtimen kautta verkkoon. Näin datakeskuksen "sivutuotteena" syntyvä lämpö korvaa kotitalouksien tai teollisuuden erillisen lämmitystarven[1][4].

- **Teollisuusyritysten prosesseihin**: Jos läheisyydessä on teollisia prosesseja, jotka tarvitsevat lämpöä (esim. paperitehdas, kemiantehdas), datakeskukselta voitavien lämmön hinta ja energiapotentiaali voidaan sovittaa prosesseille[2][3].

- **Paikallisiin kiinteistöihin**: Kasvihuoneet, liikuntahalleja tai asuinrakennuksia voidaan lämmittää datakeskuksesta tulevalla lämmöllä, joko suoraan tai lmppumpun kautta[1].

**Arkkitehtuuri ja rajapinnat**:

Hukkalämmön hyödyntämisen käytännön toteutus vaatii:
- **Lämpötila**: Poistettava lämpö on tyypillisesti 25–35 °C:n välillä (jäähdytysveden poistettava lämpötila). Tämä riittää usein käyttötarkoituksiin, mutta joissakin teollisuusprosseissa voidaan tarvita korkeampaa lämpötilaa → lmppumppu tarvitaan, mikä kuluttaa sähköä[1][2].

- **Mitattava energia (MWh)**: Hukkalämmön otto mitataan lämpömittareilla ja virtausmittareilla. Energiamäärä lasketaan: E (MWh) = virtaus (m³/h) × ominaislämpö (kWh/m³K) × lämpötila-ero (K) × aika (h)[3].

- **Sopimus**: Datakeskuksen ja vastaanottajan välillä sovitaan lämmön toimitus, hinta, mittaus ja vastuut. Mikäli datakeskus investoi lämmönvaihtimeen ja putkiin, nämä maksut voidaan sisällyttää hintoihin tai kysyä korvausta[1].

**Hyödyntämisaste (ERF – Energy Reuse Factor)**:

ERF määritellään seuraavasti:

ERF = Hyödynnetty energia / Kokonaisenergia

Esimerkiksi:
- Kokonaisenergia: 100 MWh
- Hyödynnetty hukkalämpö: 60 MWh (johdettava kaukolämpöverkkoon, josta 60 MWh käytössä)
- ERF = 60 / 100 = 0,6 = 60 %

Hyvät tavoitteet ovat ERF > 50 %, parhaat ratkaisut voivat saavuttaa ERF > 70 %[1][3][4].

Vihreän datakeskuksen kohdalla hukkalämmön hyödyntäminen voi merkittävästi parantaa hiilijalanjälkeä, koska se korvaa erillisen lämmöntuotantoa (johon usein liittyy fossiilifuels). Lisäksi joissain tilanteissa datakeskuksesta saatava lämpö voi olla halvempaa kuin vaihtoehtoinen lämmitysenergian lähde[2][4][5].

---

## P6.5 Mittausrajat ja energiaflujen dokumentointi

Energian lähteestä käyttöön seurantaa varten on määriteltävä selkeästi mittausrajat.

**Päämitta- rajapinta**: Sähkölaskutuspiste, josta datakeskusta ruokitaan. Tässä vaiheessa mitataan kokonaisenergiakulutus. Tämä on useimmiten kantaverkko-liittymän pääkytkimen jälkeen[1][2].

**IT-energia mittauspiste**: PDU-yksiköissä tai UPS:n jälkeen mitataan, kuinka paljon energiaa IT-laitteet todella käyttävät. Ero päämitta- pisteen ja IT-energia mittauspisteen välillä kuvaa infrastruktuurihviitä[1][3].

**Jäähdytysenergia**: Mitataan jäähdytyskoneiden sähkönkulutuksesta (Pcoolt). Jäähdytyksen energian vaihtelu on merkitsevä seuraava vaihtelu IT-kuormassa ja ulkoilman olosuhteissa[1][2].

**Hukkalämmön mitta**: Lämpömittarit ja virtausmittarit datakeskuksesta poistuvassa ja palautuvassa jäähdytysvedeässä/nesteessä mittaavat siirrettävän lämmön energiamäärän[2][3].

**Dokumentointi**: Kaikki mittausrajat, niiden sijannit ja mittauslaitteiden tarkkuus dokumentoidaan. Tämä on kriittistä, koska:

- Mittariketjun eri vaiheissa voi tapahtua virheitä
- Mittareiden kalibrointi ja ylläpito vaikuttavat tuloksiin
- Energiaraportoinnissa on tärkeä osata selittää, mistä luvut tulevat[1][3][4].

Vihreän datakeskuksen mittausjärjestelmä rakennetaan niin, että energian poluista voidaan tehdä selkeä kuva: kuinka paljon rahaa tai päästöjä sidotaan IT:hen, kuinka paljon jäähdytykseen ja muuhun. Nämä tiedot auttavat sekä operointitimiä että johtoa tekemään perusteltuja optimointipäätöksiä[2][3][5].

---

## P6.6 Yhteenveto energian jakautumisesta ja säästöpotentiaalista

Datakeskuksen energiakulutus jakaantuu IT-laitteisiin, sähkönjakelun hviille, jäähdytykseen ja muihin komponentteihin. Vihreän datakeskuksen näkökulmasta jokaisen komponentin energiatehokkaaseus on tärkeä:

- **IT-laitteiden valinta**: Uudet, energiatehokkaatSam laitteet
- **Sähkönjakelussa**: Modernit muuntajat, UPS-järjestelmät, lyhyet jakelureitit
- **Jäähdytys**: Vapaajäähdytysten hyödyntäminen, tehokas ilmankierto, hyvä COP
- **Hukkalämmön hyödyntäminen**: Kaukolämpöliittymät, teollisuusprosessit

Mittarit PUE, CUE, ERF ja WUE tarjoavat välineet seurata edistymistä. Riippuen datasalin sijainnista ja tavoitteista, eri tekijöille voidaan antaa eri painotus. Suomessa viileä ilmasto ja mahdollisuus vapaajäähdytykseen sekä kaukolämpöverto tekevät hukkalämmön hyödyntämisestä erityisen potentiaalista vihreille datakeskuksille[1][2][3][4][5].

---

## P6 Lähdeviitteet

[1] Energy efficiency and low carbon enabler: Green IT framework for data centers considering green metrics. Uddin, M., Rahman, A. A. (2012). Renewable and Sustainable Energy Reviews, 16(6), 4078–4094.

[2] Data Center Handbook. Geng, H. (Ed.). (2015). John Wiley & Sons.

[3] Information technology – Data centre facilities and infrastructures – Part 4: Key performance indicators. EN 50600-4. CENELEC. European Committee for Electrotechnical Standardization.

[4] Achieving Sustainability in Computing by Minimizing Data Center Carbon Footprints. Sabree, R. M. S. (2025). Journal of Information Processing and Management.

[5] Green data centers: Advancing sustainability in the digital era. Elavarasi, J., Thilagam, T., Amudha, G., et al. (2025). In Proceedings of the International Conference on Trends in Material Science and Inventive Materials (ICTMIM-2025), pp. 1817–1823. IEEE.

---

# P7 Datakeskusten energiatehokkuuden mittaaminen

## Tavoite

Kuvata, mitkä ovat energiatehokkuuden keskeisimmät mittarit EN 50600-4 -standardin mukaisesti, miten ne määritellään ja mitataan, mitkä ovat mittauspisteet, ja miten mittareiden avulla voidaan seurata ja raportoida datakeskuksen vihreyttä johdonmukaisesti. Luku yhdistää aiempien lukujen (P1–P6) käsitteet praktiikan tasolle.

## Luku kattaa

- EN 50600-4 -standardin pääkäsitteet ja mittarit
- PUE (Power Usage Effectiveness) – määritelmä, mittaus, tulkinta
- CUE (Carbon Usage Effectiveness) – päästöintensiteetti
- WUE (Water Usage Effectiveness) – vedenkulutus
- ERF (Energy Reuse Factor) – hukkalämmön hyödyntäminen
- REF (Renewable Energy Factor) – uusiutuvan energian osuus
- Mittauspistemarkarat ja mittalaitteet
- Mittausjaksojen valinta ja raportointi
- Lähettietohyväksi ja raportoinnin läpinäkyvyys

## Tuotokset – dokumentoitavat päätökset

- Valitut mittarit ja perustelut valinnoille
- Mittauspisteiden määritys ja sijoitus datakeskukseen
- Mittauslaitteiden tyypit, tarkkuusvaatimukset ja kalibrointitiheys
- Mittausjaksojen valinta (tunti, päivä, viikko, kuukausi, vuosi)
- Mittarikorit ja laskentakorkeimet
- Raportoinnin muoto ja säilytys
- Läpinäkyvyyden periaatteet ja ulkoisen auditoinnin järjestäminen
- Perustuu P1.4:n ja EN 50600-4 -standardiin

---

## P7.1 EN 50600-4 -standardin yleiskatsaus

EN 50600-4 on Eurooppalainen standardi, jonka otsikko on "Information technology – Data centre facilities and infrastructures – Part 4: Key performance indicators". Standard määrittää energiatehokkuuteen, ympäristövaikutuksiin ja resurssienkäyttöön liittyviä keskeisiä mittareita datakeskuksille[1].

Standardin tavoite on:

- Tarjota yhtenäiset, vertailukelpoiset mittarit eri datakeskuksille
- Mahdollistaa omistajille ja operaattoreille seurata omaa kehitystään ajan funktiona
- Antaa sijoittajille ja stakeholdereille läpinäkyviä tietoja datakeskuksen hyötysuhteesta
- Tukea regulaatiovaatimuksien noudattamista ja raportointi[1][2].

Standard määrittää kuutta pääkategoriaa mittareille:

1. **Energia (Energy)**: PUE, REF
2. **Hiilidioksidi-päästöt (Carbon)**: CUE
3. **Vesi (Water)**: WUE
4. **Jäte (Waste)**: WaUE (Waste Usage Effectiveness)
5. **Maankäyttö (Land)**: LUE (Land Usage Effectiveness)
6. **Materiaalit ja resurssit**: RUE (Resource Usage Effectiveness)

Tässä oppaassa keskitytään energiaan liittyviin mittareihin (PUE, REF), hiilijalanjälkeen (CUE), vedenkulutukseen (WUE) ja energian uudelleenkäyttöön (ERF), sillä nämä ovat datakeskusten vihreän suunnittelun kannalta keskeisimpiä[1][3].

---

## P7.2 PUE – Power Usage Effectiveness

**Määritelmä ja laskenta**:

PUE = Kokonaisenergia [MWh] / IT-energia [MWh]

PUE mittaa, kuinka suuri osuus datakeskukseen syötetystä energiasta menee IT-laitteille, ja kuinka suuri osuus menee infrastruktuurihviille (jäähdytys, sähkönjakelu jne.)[1][2].

**Mittauspisteet**:

- **Kokonaisenergia**: Mitataan datakeskusta ruokkivasta sähköliittymästä (pääkytkimen jälkeen). Päämitta.
- **IT-energia**: Mitataan PDU-yksiköistä (Power Distribution Unit), joista energia menee palvelinkaappeihin ja IT-laitteisiin. Tai vaihtoehtoisesti UPS-lähdöistä, riippuen mittausrajauksesta[1][3].

**PUE:n tulkinta**:

- **PUE 1,0**: Ihanteellinen, kaikki energia menee IT:lle, ei infrastruktuurihviitä (käytännössä mahdoton)
- **PUE 1,2–1,3**: Erinomaisuus (hyperscale-palveluntarjoajat, optimoitu ilmasto)
- **PUE 1,4–1,6**: Hyvä (moderni, tehokas datakeskus)
- **PUE 1,8–2,0**: Keskimääräinen (perinteinen yritysdata sali)
- **PUE > 2,5**: Heikko (vanhentunut, ylimitoitettu infrastruktuuri)

Suomalaisten datakeskusten tavoite voi olla PUE 1,3–1,5, kun otetaan huomioon ilmastotekijät ja infrastruktuurin korkea redundanssi[1][2][4].

**PUE:n mittaus ja raportointijaksot**:

PUE voidaan raportoida useilla aikaväleillä:

- **Tunti**: Hetkellinen PUE, vaihtelee kuormituksen mukaan
- **Päivä**: Päivittäinen PUE, osoittaa päivän sisäisiä vaihteluja
- **Kuukausi**: Kuukausin PUE, sopii yleiseen seuraantaan
- **Vuosi**: Vuosittainen PUE, kuvaa kokonaisperformanssia sesonkivaihtelun kanssa

Tyypillisesti raportoitava PUE on kuukauden tai vuoden keskiarvo, koska se tasoittaa kuormien vaihtelun ja antaa stabiilin kuvan[1][3].

---

## P7.3 CUE – Carbon Usage Effectiveness

**Määritelmä ja laskenta**:

CUE = CO₂-päästöt [kgCO₂e] / IT-energia [kWh]

CUE mittaa, kuinka paljon hiilidioksidi-ekvivalenttisia päästöjä syntyy jokaista IT-energian kilowattituntia kohden. Tämä riippuu sekä energian määrästä että energian alkuperästä (päästöker roin)[1][2][3].

**Päästökerroin**:

Jokaisen sähköverkon osalla on päästökerroin (gCO₂/kWh), joka ilmoittaa, kuinka paljon hiilidioksidipäästöjä syntyy sähköä tuotettaessa. Suomessa päästökerroin on erittäin alhainen (noin 30–50 gCO₂/kWh), koska iso osa sähköstä tuotetaan uusiutuvalla energialla (vesi- ja tuulivoima) sekä ydinvoimalla. Muissa Euroopan maissa päästökertoimet ovat korkeampia (100–400 gCO₂/kWh)[1][4][5].

**CUE:n laskentaesimerkki**:

- IT-energia kuukautta kohti: 50 MWh = 50 000 kWh
- Sähkön päästökerroin: 40 gCO₂/kWh (Suomi)
- CO₂-päästöt: 50 000 kWh × 40 g/kWh = 2 000 000 gCO₂e = 2 tCO₂e
- CUE = 2 000 000 g / 50 000 000 Wh = 0,04 kgCO₂e/kWh = 40 gCO₂e/kWh

**CUE:n parantaminen**:

CUE voidaan parantaa:

1. **Energiatehokkuuden parantaminen** (PUE-laskut) – vähemmän kokonaisenergian tarvitseminen
2. **Uusiutuvan energian käyttö** – valkoisella energialla syötetyllä datakeskuksella CUE on pienempi
3. **Päästöjen vähennyspyrkimykset muualla** (esim. varavoimageneraattorien oikea huolto vähentää turhia testikäyntejä ja niihin liittyviä päästöjä)

Vihreillä datakeskuksilla CUE-tavoitetta korostekin usein energiatehokkuuden (PUE) lisäksi, koska hiilijalanjälki on loppulinja mittari yhteiskunnalliselle vastuulle[1][2][3].

---

## P7.4 WUE – Water Usage Effectiveness

**Määritelmä ja laskenta**:

WUE = Vedenkulutus [m³] / IT-energia [kWh]

WUE mittaa, kuinka paljon vettä käytetään jokaista IT-energian yksikköä kohden. Jäähdytys usein kuluttaa enemmän vettä kuin muut prosessit, erityisesti tuuletinhöyrystinjäähdytyksessä[1][2].

**Vedenkulutus datakeskuksissa**:

Vesi kuluu pääasiallisesti:

- **Jäähdytyskoneiden kylmäainerekissä**: Höyrystys vaatii veden ottamista ja sitä haihtuu
- **Tornityyppisten jäähdytyslaitteissa**: Vesi kierrätetään ja haihdutetaan, mistä syntyy merkittävä vedenkulutus
- **Puhdistus ja ylläpito**: Pienempi osuus

Vesi voidaan ottaa useista lähteistä:
- **Makea vesi**: Kunnallisesta vedenjärjestelmästä (kalliinta ja kestämätöntä monilla alueilla)
- **Kierrätystä vettä**: Teollisuuden tai rakentamisen vedestä
- **Sadevesi**: Keräilty katolta
- **Merivedesta suolatonnettuava vesi**: Kalliihinta, mutta vaihtoehto rannikkoalueilla

Hyvin varustettu vihreä datakeskus minimoi makean veden käytön ja käyttää kierrätettyä tai sadevettä mikä mahdollista[1][2][3].

**WUE:n tavoitearvot**:

- **WUE < 0,5 m³/MWh**: Erinomaisesti (esim. vapaajäähdytys, joka ei häivitä tai kierrätettävä vesi)
- **WUE 0,5–1,0 m³/MWh**: Hyvä
- **WUE 1,0–2,0 m³/MWh**: Keskimääräinen
- **WUE > 2,0 m³/MWh**: Heikko (korkea veden kulutus)

Suomessa, jossa vesivarat ovat runsaat ja vapaajäähdytys mahdollista, WUE voi olla erityisen hyvä[1][2][3].

---

## P7.5 ERF – Energy Reuse Factor

**Määritelmä ja laskenta**:

ERF = Hyödynnetty energia [MWh] / Kokonaisenergia [MWh]

ERF mittaa, kuinka suuri osa datakeskuksessa käytetystä energiasta hyödynnetään (esim. hukkalämmö kaukolämpöverkkoon). Tämä on avainmittari vihreille datakeskuksille, joissa hukkalämmön hyödyntäminen on osaa strategiaa[1][2][3].

**Hyödynnetyn energian määritelmä**:

Hyödynnetyksi energiaksi luetaan:

- **Hukkalämpö, joka johdetaan kaukolämpöverkkoon**: Mitataan lämpömittareilla ja virtausmittareilla
- **Muut uudelleenkäytön muodot**: Esim. teollisuusprosesseihin johdettu lämpö, kasvihuoneiden lämmitys

Hyödynnettävää energiaa lasketaan:

Hyödynnetty energia = virtaus (m³/h) × ominaislämpö (kWh/m³·K) × lämpötilaero (K) × aika (h)

Esimerkiksi:
- Virtaus: 50 m³/h
- Lämpötilaero: 10 K
- Ominaislämpö (vedelle): ~0,00279 kWh/m³·K
- Hyödynnetty teho: 50 × 0,00279 × 10 = 1,395 kWh/h = noin 1,4 kWth (hetkellinen)

Tätä integroidaan ajassa saadakseen kokonaisenergia jaksolla[1][2][3].

**ERF:n tavoitearvot**:

- **ERF > 50 %**: Hyvä (merkittävä osa energiasta hyödynnetään)
- **ERF > 70 %**: Erinomaisuus (lähes kaikki mahdollinen energia hyödynnetään)
- **ERF = 0 %**: Ei hyödyntämistä (kaikki hukkalämpö menee ilmaan)

Datakeskuksille, joilla on kaukolämpöliityntä, ERF-tavoite on usein > 50 %. Suomessa kaukolmpverkkoja on paljon, mikä tekee ERF:n parantamisen helpommaksi kuin monissa muissa maissa[1][2][4][5].

---

## P7.6 REF – Renewable Energy Factor

**Määritelmä ja laskenta**:

REF = Uusiutuvalla energialla tuotettu sähkö [MWh] / Kokonaisenergia [MWh]

REF mittaa, kuinka suuri osuus datakeskukseen syötetystä sähköstä tuotetaan uusiutuvista lähteistä (aurinko, tuuli, vesi, biomassa jne.)[1][2].

**Uusiutuvan energian todentaminen**:

Uusiutuvaa energiaa voidaan hankkia usealla tavalla:

- **Sähköpostsopichus (PPA – Power Purchase Agreement)**: Datakeskus sopii suoraan uusiutuvan energian tuottajan kanssa ostaa sen tuotantoa
- **Alkuperätakuu (Green-O/GoO – Guarantees of Origin)**: Sähkömarkkinalassa käytettävä instrumentti, jolla vähennetään, että ostettu sähkö tulee uusiutuvasta lähteestä. GoO-todistuksia myydään erikseen sähköstä, ja ostamalla ne voidaan dokumentoida uusiutuvan energian osuus[1][2][3].
- **Oma tuotanto**: Datakeskuksen kattoon asennetut aurinkopaneelit tai omat tuuliturbiinit
- **Verkosta ostettu sähkö**: Joissain maissa, esim. Norjassa, verkkoenergia on pitkälti uusiutuvaa

**REF:n tavoitearvot**:

- **REF 100 %**: Täysin uusiutuvalla energialla toimiva datakeskus (tavoitteellinen, vaikea saavuttaa käytännössä ilman omaa tuotantoa)
- **REF 80 %**: Hyvä tavoite, usein saavutettavissa PPA-sopimuksilla
- **REF 50 %**: Kohtuullinen tavoite, vähintään näin paljon suuri yritys voisi tavoitella
- **REF < 20 %**: Heikko, ei merkittävää satsausta uusiutuville

Suomessa, jossa sähkötarjonnassa on merkittävä uusiutuvan energian osuus (vesivoimasta tuulivoimaan), datakeskukselle on suhteellisen helppo saavuttaa korkea REF ilman omia investointeja. Monissa Suomen datakeskuksissa REF on jo 70–90 % ilman erityisiä pyrkimyksiä[1][3][4].

---

## P7.7 Mittausjärjestelmän rakentaminen ja mittalaitteet

**Mittauspisteiden määritys**:

Vihreän datakeskuksen mittausjärjestelmä rakennetaan siten, että voidaan jäljittää energia mistä tahansa pisteestä mihin tahansa. Tyypilliset mittauspisteet:

1. **Päämitta**: Sähkölaskutuspiste, datakeskusta ruokkiva liittymä
2. **Muuntajien jälkeen**: Päämuuntajan lähdöt (jos useita muuntajia)
3. **UPS-lähdöt**: Kriittisten kuormien sähkö
4. **PDU-yksiköt**: Palvelinkaappien energiansyöttö
5. **Jäähdytyskoneet**: Erillisesti jäähdytysyksikköjen sähkö
6. **Muut kuormat**: Valaistus, toimistot, turvallisuus (jos halutaan erillisesti)
7. **Lämmön mittaus**: Datakeskuksesta poistuvien ja palautuvien jäähdytysnesteissä olevat lämpömittarit[1][2][3].

**Mittauslaitteet**:

- **Kolmivaiheisten johdokon virta, jännite ja teho**: Ammerit, voltmetrit, wattmittarit tai älykkäät mittarit
- **Energialaskurit**: Erilliset kWh-laskurit, joista voidaan lukea kumulatiivinen energia
- **Lämpömittarit (RTD, Pt100 tai termoparit)**: Lämpötilan mittaus nesteissä
- **Virtausmittarit**: Jäähdytysnesteen virtauksen mittaus (vortex-, magneettinen tai ultraääni-mittari)
- **Dataloggerit ja BMS (Building Management System)**: Mittareiden lukemien tallentaminen ja analysointi[1][2][3].

**Mittalaitteiden tarkkuus ja kalibrointi**:

- **Vaatimukset**: EN 50600-4 suositte mittareiden tarkkuutta vähintään ±1–3 % luokka, riippuen mittarityypistä
- **Kalibrointi**: Mittarit kalibroitava säännöllisesti (tyypillisesti 1–2 vuoden välein) viranomaisesti hyväksytyissä kalibrointilaboratoriossa
- **Dokumentointi**: Kalibroinnin todistukset säilytettävä ja raportoinnissa mainittava, että mittaukset on kalibroitu[1][3].

---

## P7.8 Mittausjaksojen valinta ja raportointi

**Mittausjaksojen valinta**:

Mitattuja energia-arvoja voidaan raportoida useilla aikaväleillä:

- **Reaaliaikainen (sekunnin/minuutin tasolla)**: Operointitiimin käyttöön, hälytykset ja ohjaus
- **Tunti**: Yksityiskohtainen seuranta, kuormitusprofiilin analyysi
- **Päivä**: Päivittäinen raportointi johtohallinnon näkyvyyteen
- **Viikko**: Trendianalyysi ja viikoittaiset kokoukset
- **Kuukausi**: Tavanomaisin raportointijaksо, vertailukelpoinen muihin datakeskuksiin
- **Vuosi**: Vuosiraportointi osakkeenomistajille ja regulaatoreille

PUE:ta raportoitaessa tulisi käyttää vähintään **kuukauden pituisia jaksoja**, koska lyhyemmät jaksot sisältävät paljon satunnaisvaihtelua. Vuosittainen PUE on paras mittari pitkän aikavälin kehityksestä[1][2][3].

**Raportoinnin muoto ja dokumentointi**:

- **Mittarikortti**: Jokaisen mittarin (PUE, CUE, WUE, ERF, REF) arvo raportoidaan selkeästi
- **Laskentamenetelmä**: Raportissa selitetään, mistä lukemat tulevat ja miten ne on laskettu
- **Mittauspisteet ja rajaukset**: Dokumentoidaan, mitkä energiat sisältyvät "kokonaisenergian" määritelmään ja mitkä IT-energian määritelmään
- **Trendit ja analyysi**: Kuvaajat, jotka osoittavat kehityksen ajan funktiona
- **Epävarmuudet ja huomautukset**: Jos mittausaika on poikkeuksellinen (esim. jokin laite oli huollossa), merkitään huomio[1][2][3].

**Läpinäkyvyys ja ulkoinen auditointi**:

Vihreän datakeskuksen mittareiden uskottavuuden lisäämiseksi suositellaan:

- **Kolmannen osapuolen auditointi**: Ulkopuolinen auditointitaho tarkistaa mittausjärjestelmän ja raportit vuosittain tai kahden vuoden välein
- **Avoin dokumentointi**: Mittauspisteet, mittauslaitteet ja laskentamenetelmät dokumentoidaan selkeästi ja asiakirjat ovat saatavilla auditointitiimille
- **Standardinmukaisuus**: Mittaukset suoritetaan EN 50600-4 -standardin mukaisesti ja tämä dokumentoidaan
- **Johtue kommunikaatio**: Stakeholdereille (osakkeenomistajat, asiakkaat, viranomaiset) raportoidaan mittarituloksia rehellisesti ja kontekstualisoituna (esim. kuinka paljon kuormitus vaikuttaa PUE:hun)[1][2][4].

---

## P7.9 Mittareiden tulkinta ja benchmarking

**Omien mittareiden vertailu tavoitteisiin**:

Kun datakeskus on saavuttanut vakaan operointivaiheen, sen mittareita voidaan verrata:

- **Asetettuihin tavoitteisiin**: Esim. "Tavoite oli PUE 1,4, mitä saavutimme?"
- **Industriaaliseen benchmark-tietoon**: Esim. kansainväliset tutkimukset raportoivat "Datacenter industry average PUE on 1,7"
- **Omaan historiaan**: "Viime vuonna PUE oli 1,5, nyt se on 1,42, eli parannus 5 %"
- **Kilpailijoihin**: Jos tietoa on saatavilla, voidaan verrata muihin datakeskuksiin (vaikkakin täydellinen vertailu on monesti mahdotonta, koska olosuhteet eroavat paljon)[1][2][3].

**Kontekstualisointi ja tekijät, jotka vaikuttavat mittareihin**:

On tärkeä ymmärtää, mitä tekijöitä mittareihin vaikuttaa:

- **Ulkoilman olosuhteet**: Viileä ilmasto parantaa PUE:ta (free cooling), kosteus vaikuttaa lämmönsäätöön
- **Kuormitusaste**: Hetkellisesti alhainen kuormitus voi parantaa PUE:ta (jos varakapasiteetti ei kuluta energiaa), mutta pitkään alhainen kuormitus voi huonontaa sitä (tyhjäkäynti)
- **Varmistusperiaate**: Redundanssit (N+1, 2N) nostavat PUE:ta, koska varakapasiteetti kuluttaa energiaa
- **Hukkalämmön hyödyntäminen**: Jos ERF on korkea, kokonaisenergia voi näyttää korkealta, mutta hyödyllistä energiaa tuotetaan enemmän

Hyvä mittauksesta raportointi selittää nämä kontekstit, eikä vain raportoi numeroa[1][2][3][4].

---

## P7.10 Raportointi ja sertifiointi

**Sisäinen raportointi**:

Datakeskuksen operoinnin johdolla tulisi olla säännöllinen (vähintään kuukauden) raportointi mittareiden tilasta. Raporttiin sisältyy:

- Kuluvan kuukauden mittarit (PUE, CUE, WUE, ERF, REF)
- Trendit (viimeisen 12 kuukauden keskiarvot)
- Analyysi: "Miksi PUE nousi/laski?", "Miten voimme parantaa?"
- Toimenpiteet: "Seuraava kuukausi vaihdamme seuraavat komponentit, jotka voivat parantaa PUE:ta"[1][2].

**Ulkoinen raportointi**:

Datakeskuksen omistaja/asiakas raportoi mittareitaan:

- **Vuosikertomus**: Johtohallinnon tai osakkeenomistajien tiedoksi
- **Ympäristöraportit**: Jos datakeskus on merkittävä energiankuluttaja tai on asettanut ympäristötavoitteita, raportointi ympäristöviranomaisille (esim. EN ISO 14001 -sertifikaatin puitteissa)
- **Asiakkaiden tiedoksi**: Jos datakeskus on colocation- tai pilvipalvelupalvelun tarjoaja, asiakkaat voivat vaatia energiatehokkuustietoja[1][3][4].

**Sertifiointi ja todentaminen**:

Datakeskukset voivat hakea sertifikaatteja, jotka todentavat ympäristöperiaatteet:

- **ISO 50001 (Energianhallintajärjestelmä)**: Osoittaa, että datakeskuksella on dokumentoitu energianhallinnon prosessi
- **ISO 14001 (Ympäristöjärjestelmä)**: Laajempi ympäristövastuu
- **LEED / BREEAM (rakennussertifikaatit)**: Vihreät rakennustodistukset, jotka sisältävät energiatehokkuuskriteere
- **EN 50600-4 mukaisuustodistus**: Ulkopuolinen auditiointi, joka varmentaa, että mittaukset ja laskenta noudattavat standardia[1][2][3].

Vihreän datakeskuksen näkökulmasta sertifiointi lisää uskottavuutta ja osoittaa sitoutumista jatkuvaan parantamiseen[1][4].

---

## P7.11 Jatkuvan parantamisen prosessi mittareiden kautta

Mittarit eivät ole vain raportointia varten – niiden avulla voidaan ohjata jatkuvaa parantamista:

1. **Mittaa**: Kerää säännöllisesti tiedot PUE, CUE, WUE, ERF, REF:stä
2. **Analysoi**: Vertaa tavoitteisiin, etsi poikkeamat ja niiden syyt
3. **Toimenna**: Tuotanto parannustoimenpiteet: esim. "lämpötila nousee johtaa alarmin, tutkitaan jäähdytyksen tehokkuutta"
4. **Todennaavat: Mitaa uudelleen saadaksesi todisteen parannuksista
5. **Raportoi**: Kerro sidosryhmille tuloksista, ja aseta uudet tavoitteet

Tämä sykli voidaan toistaa jatkuvasti, ja se johtaa asteittaisiin mutta merkityksellisiin parannuksiin ajan mittaan[1][2][3].

---

## P7 Yhteenveto

EN 50600-4 -standardin mittarit tarjoavat kattavan kehikon datakeskusten vihreyyden mittaamiselle ja seuraamiselle. Energia (PUE, REF), hiilidioksidipäästöt (CUE), veden käyttö (WUE) ja energian uudelleenkäyttö (ERF) yhdessä antavat kokonaiskuvan siitä, miten kestävästi datakeskus toimii.

Mittausjärjestelmä on kuitenkin vain väline – todellinen arvo syntyy, kun tietoja käytetään aktiivisesti päätöksentekoon ja jatkuvaan parantamiseen. Läpinäkyvä raportointi, ulkoinen auditointi ja benchmarking auttavat sitä, että mittarit pysyvät uskottavina ja vertailukelpoisina[1][2][3].

Vihreän datakeskuksen omistajille ja operaattoreille mittareiden seuranta on jokapäiväisen toiminnan osa. Ne ohjailevat investointipäätöksiä (esim. "onko uuden jäähdytyskoneen hankkinta kannattavaa?"), operointioptimointeja (esim. "kuinka säädämme lämpötilatavoitteita?") ja pitkän aikavälin strategiaa (esim. "millainen datakeskus haluamme olla 5 vuoden päästä?")[1][2][3][4].

---

## P7 Lähdeviitteet

[1] Information technology – Data centre facilities and infrastructures – Part 4: Key performance indicators. EN 50600-4. CENELEC. European Committee for Electrotechnical Standardization. n.d.

[2] Data Center Handbook. Geng, H. (Ed.). (2015). John Wiley & Sons.

[3] Sustainability-aware Resource Provisioning in Data Centers. Wang, J., Palanisamy, B., Xu, J. (2020). In 2020 IEEE 6th International Conference on Collaboration and Internet Computing (CIC), pp. 60–67. IEEE.

[4] Achieving Sustainability in Computing by Minimizing Data Center Carbon Footprints. Sabree, R. M. S. (2025). Journal of Information Processing and Management.

[5] Green data centers: Advancing sustainability in the digital era. Elavarasi, J., Thilagam, T., Amudha, G., et al. (2025). In Proceedings of the International Conference on Trends in Material Science and Inventive Materials (ICTMIM-2025), pp. 1817–1823. IEEE.

