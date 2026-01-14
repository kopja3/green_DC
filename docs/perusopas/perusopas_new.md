Perusopas vihreän datakeskuksen rakentamiseksi Suomessa
P1 – Johdanto vihreään datakeskukseen
P1.1 Miksi perusopas?

Tämä perusopas tukee ympäristöystävällisen ja energiatehokkaan datakeskuksen suunnittelua ja toteutusta Suomen olosuhteissa. Opas jäsentää keskeiset päätökset vaiheisiin ja kytkee ne mitattaviin suureisiin: energia (E), teho (P), kapasiteetti (C) ja palvelutaso (SLA/SLO)

. Jokainen vihreyttä koskeva päätös pyritään perustelemaan mitattavilla arvoilla, selkeillä mittausrajoilla sekä tiedonkeruulla ja -analyysillä, jotta ympäristövaikutukset voidaan todentaa datan avulla. Väitteet ja suositukset pohjautuvat julkaistuun tutkimustietoon ja standardeihin, joihin viitataan numeroviittein.

Opas on jaettu lukuihin seuraavasti (suluissa viitteitä aihetta syventäviin julkaisuihin):

    Luku 2 – Miksi datakeskus rakennetaan ja miten sijainti valitaan: datakeskusten kasvun ajurit ja sijaintipäätöksen perusteet (sähkö, verkko, viive, jäähdytys, hukkalämpö)【9】【7】.

    Luku 3 – Vihreän datakeskuksen peruselementit ja periaatteet: vihreyden osa-alueet ja käsitteet sekä miten IT, sähkö ja jäähdytys kytketään mittareihin【1】【3】.

    Luku 4 – Datakeskuksen elinkaaren vaiheet: suunnittelu, rakentaminen, käyttö ja käytöstäpoisto – vihreät käytännöt hankkeen koko elinkaaren ajan【18】【17】.

    Luku 5 – Datakeskuksen toiminta vaiheittain: miten sähkö muuttuu palveluiksi ja lopulta lämmöksi, sekä hukkalämmön hyödyntäminen ja jatkuva optimointi operoinnissa【3】【13】.

    Luku 6 – Energian kulutus ja uudelleenkäyttö: mistä datakeskuksen energiankulutus koostuu, kuinka kulutus vaihtelee ja miten hukkalämpöä voidaan hyödyntää; energian käytön ja päästöjen kytkentä【9】【7】.

    Luku 7 – Energiatehokkuuden mittaaminen: alan keskeiset tehokkuusmittarit (PUE, WUE, CUE, REF, ERF) ja mittauspisteet sekä raportointikäytännöt ja säädösvaatimukset【23】【12】.

(Merkinnät ja tehomitoituksen symbolit on esitelty kohdassa P1.4.)
P1.2 Mikä on vihreä datakeskus?

Vihreällä datakeskuksella tarkoitetaan tässä oppaassa datakeskusta, jonka suunnittelu ja operointi perustuvat energian käytön mittaamiseen, energiatehokkuusmittareihin ja päästöintensiteetin raportointiin【1】【3】. Vihreys ei ole yksi tietty tekninen ratkaisu, vaan joukko päätöksiä ja käytäntöjä, joiden vaikutus voidaan mitata ja todentaa. Keskeistä on sitoa IT-kuorma, sähköinfra ja jäähdytys yhdeksi kokonaisuudeksi, jota johdetaan dataan perustuvilla mittareilla ja tavoitteilla. Kirjallisuudessa vihreää datakeskusta käsitellään yleensä osa-alueittain ja mittaristoina – esimerkiksi kuorman- ja kapasiteetin hallinta, sähkönsyötön hyötysuhde, jäähdytyksen ohjaus, hukkalämmön talteenotto sekä uusiutuvan energian ja päästöjen hallinta

. Tässä oppaassa vihreän datakeskuksen toteutus jaetaan samoihin osa-alueisiin:

    Kuorma ja kapasiteetti: työkuorman kuvaus, kapasiteetin mitoitus ja IT-tehon vaihtelu ajassa.

    Sähkönsyöttö ja varmistus: sähköliittymän kapasiteetti, jakeluverkko, UPS/varavoima ja häviöiden minimointi.

    Sähkön alkuperä ja päästöt: hankintatapa, uusiutuvuuden todentaminen ja päästökertoimien valinta raportointiin.

    Jäähdytys: jäähdytysarkkitehtuuri ja -menetelmät sekä jäähdytyksen sähkönkulutus suhteessa IT-tehoon.

    Hukkalämpö: lämpökuorman talteenotto, mittaus ja hyötykäyttörajapinta.

    Elinkaaren loppu: käytöstäpoisto, tietoturvallinen laitteiden poisto ja materiaalien kierrätys.

(Edellä mainittujen osa-alueiden päätöspisteet on koottu kohtaan P1.8 ja tekninen toteutus kuvataan luvussa 3.)
P1.3 Miten opasta käytetään?

Opas on kirjoitettu tukemaan datakeskushankkeen päätöksentekoa ja dokumentointia. Käytä opasta siten, että etsit kussakin vaiheessa ensin keskeisen kysymyksen, teet siihen perustuvan päätöksen ja lopuksi varmistat, että päätökselle on määritetty mitattavat lähtötiedot:

    Määritä lähtötiedot ja rajaukset. Kirjaa palvelukuorman kuvaus ja palvelutasovaatimukset. Määrittele energiankäytön mittausrajat – mistä pisteestä datakeskuksen kokonaisenergia mitataan ja mihin asti IT-energia rajataan.

    Johda mitoitusketju. Johda työkuormasta tarvittava kapasiteetti ja IT-tehon vaihtelu ajassa. Mitoita niiden perusteella sähköliittymän koko, jakelu- ja varmistusjärjestelmät sekä jäähdytys (tehomitoitusketjun symbolit on kuvattu kohdassa P1.4).

    Valitse mittarit ja todennusmenetelmät. Valitse energiatehokkuuden ja ympäristön kannalta keskeiset mittarit. Määritä kutakin varten mittauspisteet ja tiedonkeruumenetelmät. Suunnittele myös, miten ostosähkön alkuperä todennetaan ja mitkä päästökertoimet raporteissa käytetään.

Kun datakeskus otetaan käyttöön, omaksu operointiin periaate mittaa → analysoi → paranna → todenna → vakioi jatkuvan optimoinnin varmistamiseksi

. Toisin sanoen, seuraa mittareita säännöllisesti, tee tarvittavia muutoksia ja todentavia testejä, ja vakioi hyväksi havaitut käytännöt osaksi operointiprosessia.
P1.4 Datakeskuksen sähkö- ja jäähdytysinfrastruktuurin tehomitoitusketju

Datakeskuksen suunnittelussa on tärkeää ymmärtää, miten palvelukuorma lopulta määrää vaaditun sähkö- ja jäähdytyskapasiteetin. Seuraavassa määritellään oppaan kannalta keskeiset suureet ja esitetään tehomitoitusketju, eli miten työkuormasta ja palvelutasovaatimuksista johdetaan IT-teho ja edelleen infrastruktuurin mitoitusvaatimukset

:
Perustermit ja yksiköt

    Teho (P): hetkellinen sähkönsyöttö tai -kulutus. Yksikkö W (watti) ja sen kerrannaiset kW, MW.

    Energia (E): teho integroituna ajassa, eli kulutetun sähkön määrä tietyllä ajanjaksolla. Yksikkö Wh (wattitunti) ja kerrannaiset kWh, MWh, GWh (esimerkiksi 1 kWh = 1 kW * 1 h).

    IT-työkuorma L(t): datakeskukseen saapuvien palvelu- ja työpyyntöjen määrä ja ominaisuudet ajan funktiona (esim. pyyntöjä/s, transaktioita/s, eräajoja tai dataintensiivisiä siirtoja per aikayksikkö)

. Työkuorman vaihtelu ja huiput vaikuttavat suoraan tarvittavaan kapasiteettiin.

Palvelutasosopimus (SLA) ja -tavoite (SLO): sovittu palvelutaso ja yksittäinen mitattava tavoitetaso. SLA on palveluntarjoajan ja asiakkaan sopimus palvelutasosta; se voi sisältää useita SLO-tavoitteita (esim. 99,9 % kuukausittainen käytettävyys tai p95-vasteaika < 200 ms) sekä mittaus- ja raportointitavat ja mahdolliset hyvitykset ehtojen pettäessä

. Mitoituksessa käytännössä SLO-arvojen tulee täyttyä, joten ne määräävät suunnittelun lähtökohdat.

Laskentakapasiteetti (IT-kapasiteetti): IT-resurssit, joilla L(t) pystytään käsittelemään sovituilla palvelutasoilla. Käytännössä kapasiteetti tarkoittaa palvelimia (suorittimet, muisti, tallennus) ja verkkolaitteita, jotka tarvitaan kuorman kantamiseen. Kapasiteetti suunnitellaan niin, että sekä normaali kuorma että ennakoidut huiput sekä vikatilanteet voidaan hoitaa.

    Asennettu kapasiteetti (C_inst): hankittu ja asennettu kokonaiskapasiteetti (teoreettinen enimmäissuorituskyky).

    Aktiivinen kapasiteetti (C_act(t)): se osa kapasiteetista, joka on kussakin hetkessä aktiivisesti käytössä kuorman kantamiseen.

    Varakapasiteetti (C_res): kapasiteetti, joka pidetään käyttämättömänä varalla kuormahuippujen, ennusteen epävarmuuden tai vikatilanteiden varalta palvelutason takaamiseksi

        . Varakapasiteetti riippuu SLA/SLO-vaatimuksista ja valitusta varmistusperiaatteesta (esim. N+1).

    IT-teho P_IT(t): IT-laitteiden (palvelimet, tallennus, verkko) hetkellinen sähkönkulutus ajanhetkellä t. Yksikkö kW (usein puhuttaessa ”IT-kuorma” tarkoitetaan nimenomaan IT-laitteiden ottamaa tehoa).

Tehomitoitusketjun vaiheet

Tyypillinen mitoitusketju etenee seuraavasti

:

L(t) + (SLA/SLO vaatimukset) → C_act(t) + C_res → P_IT(t) → sähkö- ja jäähdytysinfrastruktuurin mitoitus

    Kuormasta kapasiteettiin: Työkuorman määrä ja palvelutasotavoitteet määräävät, kuinka suuri osa asennetusta kapasiteetista (C_inst) on pidettävä aktiivisena (C_act(t)) ja kuinka paljon varalla (C_res) kuormahuippuihin ja vikatilanteisiin

. Esimerkiksi tiukemmat saatavuusvaatimukset johtavat usein suurempaan varakapasiteettiin.

Kapasiteetista IT-tehoon: Aktiivisten resurssien määrä ja niiden kuormitusaste määrittävät IT-laitteiden tehonkulutusprofiilin P_IT(t). Tämä profiili toimii suunnittelun lähtötietona: sen huippuarvot ja vaihtelut vaikuttavat sekä sähkösyötön että jäähdytyksen mitoitukseen

.

IT-tehosta infraan: IT-tehon huiput sekä siihen liittyvät häviöt määrittävät tarvittavan sähköliittymän koon, jakelun kapasiteetin, varmistuslaitteiston mitoituksen sekä syntyvän lämpökuorman Q_th(t) (poistettava lämpöteho). Lämpökuorman perusteella mitoitetaan jäähdytysjärjestelmät

    .

Varmistusperiaatteella (esim. N+1, 2N) tarkoitetaan, että kriittinen infrastruktuuri (sähkönsyöttö, jäähdytys) suunnitellaan kestämään yksittäisen komponentin vika ilman palvelukatkoa. Varmistus lisää yleensä laitteita, jotka toimivat osakuormalla, mikä pienentää hyötysuhdetta – tämän vaikutus on tehtävä näkyväksi laskelmissa ja mittareissa

. Vihreän datakeskuksen suunnittelussa pyritäänkin optimoimaan energiatehokkuus ja varmistus samanaikaisesti eikä erillisinä vaatimuksina.
Huomio: vihreä näkökulma mitoituksessa

Edellä kuvattu tehomitoitusketju on perinteinen suunnittelumenetelmä. Vihreässä datakeskuksessa siihen lisätään muutama kriittinen lisätarkennus:

    Sähkön alkuperän todentaminen – päätetään, miten ostettu sähkö tuotetaan ja todennetaan (esim. uusiutuva energia ja alkuperätakuut).

    Energiankäytön mittausrajat – määritetään, mistä pisteestä alkaen kokonaisenergian kulutus mitataan ja mihin asti IT-energiankulutus rajataan (mitkä laitteet/häviöt sisältyvät mittauksiin).

    Hukkalämmön hyödyntämisen rajapinta – suunnitellaan, miten poistuva lämpöenergia kerätään talteen ja toimitetaan hyötykäyttöön sekä missä vastuujako luovutuksessa on.

Mittausraja määrittää, mitkä energiavirrat sisällytetään tehokkuuslaskelmiin kuten PUE:hen. Esimerkiksi kokonaisenergia voidaan mitata sähköliittymästä ja IT-energia UPS-lähdöiltä – näin PUE-lukuun sisältyvät kaikki UPS:n jälkeiset häviöt, mutta eivät sitä ennen syntyviä häviöitä

. Vihreässä datakeskuksessa mittausrajat ja -pisteet määritellään jo suunnitteluvaiheessa (ks. luku 5 ja 7).
P1.5 Taustaa: perinteinen kuorman ja kapasiteetin mitoitus

Tehomitoitusketjun alkupää – eli miten saapuvista työpyynnöistä määritetään tarvittava kapasiteetti – perustuu usein historiadataan ja kysynnän mallintamiseen. Ensin karakterisoidaan työkuorma ryhmittelemällä pyynnöt erilaisiin tyyppeihin ja arvioimalla kunkin tyypin resurssivaatimukset (esim. CPU, muisti, I/O). Tämän pohjalta tehdään kuorman ennuste tuleville jaksoille (esim. seuraavalle vuodelle) historiallisten trendien perusteella. Palvelutasovaatimukset (esim. suurin sallittu vasteaika tai pienin sallittu saatavuus) vaikuttavat siihen, kuinka paljon kapasiteettia on pidettävä jatkuvasti aktiivisena ja kuinka paljon varalla

.

Keskeisiä käsitteitä perinteisessä mitoituksessa:

    Työpyyntö (job/request): yksittäinen käsiteltävä tehtävä tai palvelupyyntö, jolle on määritelty vaaditut resurssit ja mahdollinen deadline.

    Workload characterization (työkuorman karakterisointi): prosessi, jossa työpyynnöt luokitellaan ryhmiin (tyyppien mukaan) ja kullekin ryhmälle määritetään ominainen resurssiprofiili

.

Workload prediction (työkuorman ennustaminen): menetelmät, joilla ennakoidaan tulevaa kuormitusta (pyyntömäärät ja -tyypit) historiadatan ja trendien perusteella

.

Capacity planning (kapasiteettisuunnittelu): päätös siitä, mitkä resurssit pidetään käytössä (aktiivisena kapasiteettina) ja mitkä varalla, jotta työpyynnöt voidaan ajoittaa ja sijoittaa vaatimusten ja rajojen puitteissa

    .

Historiallisesti datakeskusten kapasiteettisuunnittelussa on ilmennyt ylikapasiteettia: palvelimia pidetään käynnissä alhaisella käyttöasteella ja varakapasiteettia on paljon, mikä johtaa turhaan energiankulutukseen. Tyypillisiä palvelinkeskusten käyttöasteita on raportoitu niinkin alhaisiksi kuin 6–12 %. Huippuluokan toimijat ovat kuitenkin yltäneet huomattavasti korkeampiin käyttöasteisiin, esimerkiksi 20–40 % tasolle

. Alhainen keskikuormitus on merkittävä tehottomuuden lähde: palvelimia käy tyhjäkäynnillä, mutta sähköä kuluu silti ja jäähdytys pyörii turhaan. Energiapropotionaalisen laskennan idea on juuri tässä – ihanteellisesti palvelimen energiankulutuksen tulisi olla suorassa suhteessa sen kuormitukseen【20】【6】. Käytännössä tähän pyritään mm. konsolidoimalla kuormia harvemmille palvelimille ja hyödyntämällä tehokkaasti lepotiloja ja dynaamista tehonsäätöä (ks. luku 3).
P1.6–P1.7 (Ei erillisiä alalukuja)

(Numerot P1.6 ja P1.7 on jätetty väliin johdannon rakenteessa, sillä niiden sisältö on yhdistetty muihin osioihin.)
P1.8 Vihreän datakeskuksen elementit ja päätöspisteet

Tässä perusoppaassa vihreän datakeskuksen toteutus jäsennetään päätöspisteiksi. Alla on koottu keskeiset päätökset muodossa päätös → tuotos → viittaus, jotta lukija näkee yhdestä paikasta etenemisjärjestyksen ja kunkin vaiheen lopputulokset:

    Työkuorma ja palvelutaso → Kuormaprofiilin määritys L(t) (tyyppi- ja määrävaihtelut) sekä palvelutasorajat (esim. maksimivasteajat, min-käytettävyys) → Syöte lukuun 5 【5】

    Kapasiteettitarve → Kapasiteetti C_inst (asennettu) ja C_act + C_res (aktiivinen + varalla pidettävä kapasiteetti) → Syöte lukuun 5 【5】

    IT-tehon profiili → IT-laitteiden tehonkulutus P_IT(t) ajan funktiona (huiput ja vaihteluväli) → Syöte lukuun 5 【6】【5】

    Sähköinfran mitoitus → Liittymäteho, jakelujärjestelmä ja varmistus (UPS/varavoima, redundanssiperiaate N/N+1/2N) sekä häviöiden arviointi → Syöte lukuun 5 【2】【7】

    Sähkön alkuperä ja päästötapa → Sähkönhankintamalli (esim. oma tuotanto, PPA-sopimus, alkuperätakuut) ja valitut päästökertoimet raportointia varten → Syöte lukuun 6 【3】【7】

    Jäähdytysratkaisu → Valittu jäähdytysarkkitehtuuri (esim. ilma/vesijäähdytys, vapaajäähdytysmahdollisuus, lämmönsiirtimet) ja arvioitu jäähdytyksen sähkötehon tarve P_cool eri kuormitustasoilla → Syöte lukuun 6 【2】【8】

    Jäähdytyksen mittaus → Jäähdytysjärjestelmän mittauspisteet ja seurantasuureet (esim. jäähdytyksen sähköteho, lämpötilat, virtaukset) IT-kuorman vertailuun → Syöte lukuun 7 【2】【8】

    Hukkalämmön hyödyntäminen → Hukkalämmön talteenoton rajapinta, lämpöenergian mittaus (MWh) sekä mahdollinen lämmön vastaanottaja ja sopimusperiaatteet → Syöte lukuun 6 【2】【7】

    Mittausrajat ja -mittarit → Päätös siitä, mistä pisteestä kokonaiskulutus mitataan ja mihin asti IT-kulutus rajataan; valitaan keskeiset energiatehokkuusmittarit (kuten PUE, CUE, ERF, jne.) sekä dokumentoidaan niiden laskentasäännöt → Syöte lukuun 7 【1】【3】【2】

    Elinkaaren loppu → Käytöstäpoiston ja kierrätyksen suunnitelma: laitteiston poistoprosessit, tietoturvallinen mediahävitys ja materiaalien kierrätys sekä loppuraportointi → Syöte lukuun 4 【2】

(Huom: jäähdytysratkaisujen vaihtoehdot ja valintaperusteet käsitellään tarkemmin luvussa 6. Mittareiden määrittely ja mittauspisteet käsitellään luvussa 7.)
P1.9 Miksi sijainti käsitellään ensin?

Datakeskuksen sijaintipäätös käsitellään oppaan rakenteessa heti luvussa 2 ennen teknisiä ratkaisuja, koska sijainti määrittää monia myöhempiä reunaehtoja. Sijainti vaikuttaa esimerkiksi saatavilla olevan sähköverkon kapasiteettiin ja luotettavuuteen, sähkön hankintavaihtoehtoihin (uusiutuvan energian saatavuus ja päästöintensiteetti) sekä jäähdytysratkaisuihin ja hukkalämmön hyödyntämismahdollisuuksiin【2】【3】【7】. Lisäksi sijainti kytkeytyy palvelun viive- ja saavutettavuusvaatimuksiin: jos käyttäjille taataan erittäin matalat viiveet tai korkea saatavuus, ei kuormaa voida vapaasti siirtää maantieteellisesti ilman vaikutusta palvelutasoon【5】【3】. Siksi sijainti luo pohjan vihreälle suunnittelulle – määrittäen energian saatavuuden ja hinnan, paikalliset ympäristömahdollisuudet (esim. vapaajäähdytyksen tuntipotentiaali) sekä yhteistyömahdollisuudet (hukkalämmön jakelu), joihin seuraavissa luvuissa rakennetaan ratkaisut.
P2 – Miksi datakeskus rakennetaan ja miten sijainti valitaan

Datakeskusten merkitys kasvaa jatkuvasti digitaalisten palveluiden ja pilvipalveluiden kysynnän myötä. Samalla niiden energiankulutus on noussut keskeiseksi suunnittelukriteeriksi, sillä sähkön kulutus vaikuttaa suoraan käyttökustannuksiin ja hiilijalanjälkeen. Vuonna 2013 Yhdysvaltain datakeskukset kuluttivat arviolta ~91 TWh sähköä, ja vuodelle 2020 ennustettiin ~140 TWh【4】. Myös globaalilla tasolla datakeskusten sähkönkulutuksen osuuden on arvioitu kasvavan merkittävästi lähivuosina【9】. Huomattava osa nykykulutuksesta ei kuitenkaan johdu pelkästään laskentakuorman kasvusta, vaan rakenteellisesta tehottomuudesta: resursseja ylivarataan, kapasiteettia pidetään tyhjäkäynnillä ja käyttöaste jää matalaksi, mikä lisää turhaa energiankulutusta myös jäähdytyksessä ja sähkönjakelussa. Tyypillinen palvelinkeskus käyttää vain pienen osan kapasiteetistaan, kun taas parhaat toimijat ovat onnistuneet nostamaan käyttöasteita selvästi korkeammiksi

. ”Vihreän datakeskuksen” rakentamisen perusidea onkin tuottaa sama palvelu pienemmällä energialla – joko parantamalla käyttöastetta (esim. konsolidointi, virtualisointi, kuormanohjaus) tai vähentämällä infrastruktuurin häviöitä ja jäähdytystarvetta, mieluiten molempia【3】.
P2.1 Tarpeet ja tavoitteet

Ennen datakeskushankkeen käynnistämistä on syytä kirkastaa, miksi uusi datakeskus rakennetaan. Tyypillisiä syitä ovat esimerkiksi liiketoiminnan tarpeet (kasvava laskentakapasiteetin tai tallennustilan tarve), tietoturva- ja suvereniteettivaatimukset (data halutaan omaan hallintaan ja Suomen lakien piiriin) sekä kustannus- tai tehokkuussyyt (halutaan pienentää pitkän aikavälin kuluja ja ympäristövaikutuksia). Vihreän datakeskuksen näkökulmasta keskeinen tavoite on usein tuottaa IT-palvelut energiatehokkaammin kuin aiemmin. Jos kyseessä on olemassa olevan kapasiteetin korvaaminen, voidaan tavoitteena olla energiankulutuksen ja päästöjen leikkaaminen esimerkiksi konsolidoimalla useita vanhoja konesaleja yhteen uuteen tehokkaampaan keskukseen. Uutta datakeskusta suunniteltaessa tulee asettaa myös ympäristötavoitteet: esimerkiksi uusiutuvan energian osuus 100 %, PUE alle tietyn rajan, tietyn määrän hukkalämmön hyödyntäminen, jne. Nämä tavoitteet kannattaa kirjata ylös jo hankkeen lähtötilanteessa, sillä ne ohjaavat sekä sijaintipäätöstä että teknisiä valintoja myöhemmin【18】. Lisäksi on hyvä arvioida, voitaisiinko tarpeeseen vastata muuten kuin oman datakeskuksen rakentamisella – esimerkiksi hyödyntämällä colocation-palveluja tai julkista pilvi-infrastruktuuria. Oman datakeskuksen rakentaminen on perusteltua vain, jos se tuo lisäarvoa esimerkiksi ohjattavuuden, suorituskyvyn, tietoturvan tai kustannustehokkuuden suhteen verrattuna vaihtoehtoihin.
P2.2 Sijaintipäätöksen perusteet

Kun datakeskuksen rakentamistarve on todettu ja tavoitteet määritelty, seuraava kriittinen kysymys on: minne datakeskus sijoitetaan? Sijainti vaikuttaa ratkaisevasti sekä teknisiin että taloudellisiin reunaehtoihin. Tutkimusten perusteella sijaintiin liittyvät tekijät voidaan jakaa neljään pääkokonaisuuteen ja yhteen rajoitteeseen【3】【2】【7】:

    Sähköverkko: Paikallisen sähköverkon kapasiteetti ja toimitusvarmuus. Onko alueella saatavilla riittävä liittymäteho suunnitellulle IT-kuormalle? Kuinka luotettava siirtoverkko on (onko kaksia feedereitä, rengasverkkoa tms.)? Mikä on sähkön hinta ja siirtokustannus kyseisellä alueella? Sijainti määrittää myös, kuinka nopeasti liittymä voidaan saada (rakennusaikataulu) ja millä kustannuksilla. Tuotokset: arvio sähköliittymän toteutettavuudesta (MW-määrä ja aikataulu), alustava suunnitelma mahdollisista varmistussyötöistä ja sähköverkon vaatimista investoinneista

.

Sähkön päästöt ja uusiutuvuus: Sijainnin mukaan vaihtelee saatavilla olevan sähkön päästöprofiili ja mahdollisuudet hankkia uusiutuvaa energiaa. Suomessa valtakunnanverkosta saatavan sähkön päästökerroin vaihtelee tuntikohtaisesti, mutta on pohjoismaisittain alhainen (~100–200 gCO₂/kWh alueella) verrattuna moniin muihin maihin【7】. Sijainti määrittää myös, voiko datakeskus hyödyntää paikallista uusiutuvaa tuotantoa (esim. tuuli-/aurinkopuistoa) tai tehdä suoran hankintasopimuksen (PPA) läheisen voimalan kanssa. Tuotokset: päätös sähkön hankintatavasta (ostosähkö vs. oma tuotanto) ja uusiutuvan energian strategiasta; arvio saatavilla olevista uusiutuvan energian lähteistä ja niiden todentamisesta (alkuperätakuut tms.)

.

Ilmasto ja jäähdytys: Paikallinen ilmasto vaikuttaa suoraan jäähdytyksen toteutukseen. Viileässä ilmastossa voidaan hyödyntää vapaajäähdytystä (ulkoilman tai ulkovesistön kylmyyttä) suuren osan vuodesta, mikä pienentää jäähdytyksen energiankulutusta. Oleellisia ovat ympäröivän ulkoilman lämpötila- ja kosteusprofiilit: kuinka monta tuntia vuodessa ollaan alle tietyntasoisen lämpötilan, entä mikä on korkea kosteuden osuus? Lisäksi tulee huomioida, tarvitaanko kosteudenhallintaa (joissain ilmastoissa liiallinen kuivuus tai kosteus vaatii energiaa tasaamiseen). Sijaintiin liittyy myös se, millaisia jäähdytysratkaisuja voidaan käyttää – esimerkiksi meriveden hyödyntäminen rannikkoseudulla tai maalämmön/maaviileän käyttö sisämaassa. Tuotokset: selvitys vapaajäähdytyksen potentiaalista (tunnetaan usein free cooling -tuntimääränä) paikallisessa ilmastossa ja siihen liittyvät oletukset (esim. sallittu lämpötila-alue laitetilassa)

【22】.

Hukkalämmön hyödyntäminen: Onko sijainnin lähellä sellaista lämmön tarvetta tai infrastruktuuria, johon datakeskuksen tuottama ylijäämälämpö voidaan järkevästi ohjata? Käytännössä tämä tarkoittaa esimerkiksi olemassa olevaa kaukolämpöverkkoa tai suurta lämpökuormaa (kuten teollisuuslaitos) suhteellisen lähellä. Sijainnin varhaisessa vaiheessa tulisi arvioida, onko realistista löytää hukkalämmön vastaanottaja, ja käynnistää keskustelut energiayhtiöiden tai muiden toimijoiden kanssa ajoissa

    . Tuotokset: alustava suunnitelma hukkalämmön talteenotosta: potentiaalisen lämmön ostajan/vastaanottajan kartoitus ja arvio tarvittavista investoinneista (lämpöverkkoon liityntä tms.).

    Reunaehto – Viive ja yhteydet: Sijainnin tulee täyttää palvelun käyttäjien viive- ja yhteysvaatimukset. Jos datakeskus palvelee esimerkiksi globaalisti käyttäjiä, liian syrjäinen sijainti voi lisätä verkkoviivettä liikaa. Suomessa sisäiset viiveet ovat yleensä matalia valokuituyhteyksien hyvän saatavuuden vuoksi, mutta globaalit palvelut voivat vaatia tietyn sijainnin lähellä pääkäyttäjäsegmenttiä. Lisäksi sijainnin tulee mahdollistaa useiden riippumattomien runkoverkkoyhteyksien saanti (teleoperaattorien reitit) ja soveltua tarvittavien kaapeliyhteyksien vedolle. Tuotokset: arvio sijainnin tietoliikenneyhteyksistä ja niiden redundanssista; latenssin osalta varmistus, että keskeiset käyttäjät saavuttavat palvelimet vaaditulla viiveellä (esim. Suomessa alle 20 ms, Euroopasta <50 ms).

Kaikki yllä mainitut tekijät tulisi arvioida esiselvitysvaiheessa läpinäkyvästi. Yksi hyväksi todettu tapa on rakentaa pisteytysmalli: määritellä kullekin osa-alueelle (sähkö, päästöt, ilmasto, hukkalämpö, yhteydet) tärkeimmät kriteerit, pisteyttää eri sijaintivaihtoehdot 1–5 asteikolla ja painottaa kriteerit liiketoiminnan prioriteettien mukaan. Tällainen pisteytystaulukko tekee päätöksestä perustellun ja auttaa kommunikoimaan sidosryhmille, miksi tietty sijainti valittiin. Pisteytysmallin lisäksi on suositeltavaa laatia sähkö- ja energiadokumentaatio (liittymäpolku, saatavuusluokka, uusiutuvan energian hankintatavat ja suunnitelma energian- ja päästöjen raportoinnista) sekä jäähdytys- ja hukkalämpökonsepti (arvio vapaajäähdytyksen hyödyntämisestä ja mahdollinen hukkalämmön integraatiopolku) jo konseptivaiheessa

. Näiden avulla varmistetaan, että myöhemmissä vaiheissa ei tule yllätyksiä esimerkiksi liittymäkapasiteetin tai lupaprosessien suhteen.
Jos sijaintivaiheen arviointi tehdään huonosti tai ohitetaan:

    Sähkönsaannin riskit toteutuvat: Tarvittavaa sähköliittymää ei saadakaan ajoissa tai toivotulla kapasiteetilla, tai sen redundanssivaatimukset (esim. kahdennettu syöttö) eivät ole toteutettavissa. Seurauksena hankkeeseen voi tulla viiveitä, lisäkustannuksia tai palvelutaso ei toteudu. Viitteet: esimerkiksi vuonna 2020 julkaistu LVM-raportti korosti sähkönsaannin varmistamisen tärkeyttä hankkeen alkuvaiheessa【7】【3】.

    Vihreät tavoitteet jäävät paperille: Uusiutuvaa energiaa koskevat lupaukset, päästöjen raportointi tai kuorman ohjaus saattavat käytännössä jäädä toteutumatta, jos sijainti valitaan näistä välittämättä. Esimerkiksi jos alueella ei ole saatavilla uusiutuvaa sähköä tai kumppania sen tuottamiseen, voi 100 % uusiutuvan tavoite kariutua. Viitteet: vihreän IT:n viitekehyksissä korostetaan, että tavoitteet pitää ankkuroida konkreettisiin toteutusmahdollisuuksiin【1】【3】【7】.

    Jäähdytys perustuu vääriin oletuksiin: Jos sijainnin ilmasto-olosuhteita ei analysoida, vapaajäähdytyksen hyöty voi jäädä saavuttamatta tai paikallinen korkea kosteuspitoisuus voi pakottaa käyttämään energiankulutusta lisääviä ilmankuivaimia. Tämä lisää sekä kulutusta että operointiriskiä (jos jäähdytyskapasiteetti aliarvioidaan). Viitteet: tapaustutkimukset osoittavat, että väärin arvioitu jäähdytysolosuhde voi heikentää energiatehokkuutta merkittävästi【2】【7】.

    Hukkalämpöpotentiaali menetetään: Mikäli läheistä lämmönkäyttäjää ei kartoiteta ajoissa tai datakeskus sijoitetaan kauas potentiaalisista hyödyntäjistä, voi ylimääräisen lämmön hyötykäyttö jäädä kokonaan toteutumatta. Jälkikäteen hukkalämmön ohjaaminen on kallista tai mahdotonta, jos alussa ei varauduta. Viitteet: useissa selvityksissä suositellaan hukkalämpöyhteistyön aloittamista heti hankkeen alussa【7】【3】.

    Verkko ja latenssi unohdetaan: Sijainti voi rajoittaa palveluiden laatua, jos yhteydet ovat heikot tai viive käyttäjiin kasvaa liian suureksi. Tällöin kuorman siirto edullisemman sähkön perässä ei onnistu ilman palvelutason laskua. Tämä paitsi nostaa operointikustannuksia, myös syö vihreän optimoinnin mahdollisuuksia (esim. ei voida ajaa työkuormaa yöllä toisaalla uusiutuvan saatavuuden mukaan). Viitteet: tutkimukset datakeskusten verkkoarkkitehtuureista korostavat, että verkon energiankulutus on huomattava tekijä ja sen optimointi edellyttää näkyvyyttä ja ohjattavuutta – mikä vaikeutuu, jos sijainti aiheuttaa latenssiongelmia【12】【7】.

(Luvun 2 tuotoksena tulisi olla:) Sijaintiselvitys, joka sisältää pisteytetyn vertailun eri vaihtoehdoista sekä valitun sijainnin perustelut sähköverkon, energian hankinnan, ilmaston, hukkalämmön ja yhteyksien osalta. Lisäksi kirjataan vihreät tavoitteet ja mittarit, joiden saavuttamista sijainti tukee (esim. mahdollistaa PUE < 1,2 vapaajäähdytyksen ansiosta tai uusiutuvan osuuden 100 % paikallisen tuotannon vuoksi).
P3 – Vihreän datakeskuksen peruselementit ja periaatteet

Vihreä datakeskus on kokonaisuus, jossa IT-kuorma, sähkönsyöttö, jäähdytys, fyysinen ympäristö sekä operoinnin ohjaus suunnitellaan yhtenä järjestelmänä. Kaikkia näitä osa-alueita yhdistää energian ja ympäristövaikutusten mittaaminen: tavoitteena on kerätä mahdollisimman paljon dataa, jolla voidaan seurata tehokkuutta ja löytää parannuskohteita. Seuraavissa alaluvuissa esitellään vihreän datakeskuksen ratkaisuja neljässä korissa: (1) IT-kerroksen energiatehokkuus, (2) resurssienhallinta, (3) lämpötilan hallinta ja jäähdytys, sekä (4) mittarit ja monitorointi. Lisäksi modernissa ajattelussa korostuu datakeskus ”yhden tietokoneen” kaltaisena kokonaisuutena (warehouse-scale computer): energiatehokkuus ja käytettävyys syntyvät laitevalintojen ohella ohjelmiston ja orkestroinnin avulla – automaattinen kuormien ja resurssien hallinta on yhtä tärkeässä roolissa kuin fyysinen infrastruktuuri

.
3.1 IT-kerros: energiatehokas laskenta ja resurssienhallinta

Tavoite: Tuottaa sama laskentapalvelu pienemmällä energialla ja minimoida ylikapasiteetti.

Palvelinlaitteiston energiatehokkuus: Nykyisissä palvelimissa on useita tekniikoita, joilla vähennetään tehonkulutusta kuorman mukaan. Dynaaminen taajuus- ja jännitesäätö (DVFS) alentaa prosessorien kellotaajuutta ja käyttöjännitettä kevyellä kuormalla, ja lepotilat (C-states) katkaisevat virran käyttämättömiltä ytimiltä, komponenteilta tai kokonaisilta palvelimilta. Näiden avulla pyritään energiapropor­tionaalisuuteen, eli että laite kuluttaa tehoa suhteessa kuormitusasteeseensa eikä ylläpidä suurta pohjakulutusta tyhjäkäynnillä. Esimerkiksi DVFS ja syvät sleep-tilat voivat vähentää prosessorin kulutusta merkittävästi silloin, kun täyttä suorituskykyä ei tarvita

.

Virtualisointi ja konsolidointi: Virtualisoinnin avulla yhdellä fyysisellä palvelimella ajetaan useita virtuaalisia palvelimia tai kontteja, jolloin laitteiston käyttöaste saadaan korkeammaksi. Konsolidointi tarkoittaa työkuormien kokoamista tarkoituksella harvemmalle fyysiselle laitteistolle niin, että osa palvelimista voidaan ajaa suuremmalla kuormituksella ja toiset laitteet voidaan sammuttaa tai pitää valmiustilassa. Tuloksena sekä IT-laitteiden että jäähdytyksen kulutus pienenee, kun vähemmän laitteita toimii vajaakäytöllä

. Resurssienhallinnan ytimessä on löytää tasapaino kapasiteetin ja kuorman välillä: kuormaa siirretään tarvittaessa palvelimelta toiselle ja vapaita laitteita siirretään lepotilaan energiankulutuksen minimoimiseksi.

Kuormien ohjaus ja tehorajoitukset: Kehittyneissä ympäristöissä voidaan toteuttaa orkestrointia, jossa työkuormia ajoitetaan ajallisesti ja paikallisesti energiakustannusten tai -lähteiden mukaan. Esimerkiksi kuormaa voidaan siirtää hetkellisesti palvelimelta toiselle, jos sähkö on halvempaa tai hiilineutraalia tietyssä paikassa tai ajankohtana. Power capping -tekniikat puolestaan rajoittavat palvelinjärjestelmän enimmäistehoa – jos tietty tehoraja uhkaa ylittyä, järjestelmä viivästyttää tai levittää kuormaa, jotta pysytään rajoissa. Tällaiset ohjausmenetelmät liittävät IT-kerroksen kulutuksen sähkön saatavuuteen ja hintaan, mikä on yksi vihreän datakeskuksen optimoinnin kulmakivistä

.

(Keskeisiä lähteitä: Sharma ym. 2017 raportoivat käytännön kokemuksia vihreästä datakeskuksesta, jossa edellä mainittuja tekniikoita hyödynnettiin onnistuneesti【18】【10】.)
3.2 Sähkö: syötöt, varmistus ja jakeluhäviöiden minimointi

Tavoite: Saavuttaa korkea käytettävyys mahdollisimman pienellä häviöenergialla, mitoittaen sähköjärjestelmä todellisen kuormitusprofiilin mukaan.

Datakeskuksen sähköinfrastruktuuri koostuu tyypillisesti ketjusta: sähköverkko → muuntajat → UPS → jakelukiskot/PDU → laitekaapit. Jokaisessa vaiheessa on häviöitä, ja lisäksi varmistuslaitteet (UPS, generaattorit) voivat lisätä tehottomuutta varsinkin osakuormalla. Vihreässä datakeskuksessa korostetaan koko sähkönsyöttöketjun hyötysuhteen mittaamista ja optimointia: muuntajien, UPS-järjestelmän ja jakelujärjestelmän häviöt tehdään näkyväksi jatkuvalla mittauksella ja pyritään minimoimaan. Esimerkiksi modernit UPSit voivat saavuttaa yli 95 % hyötysuhteen korkealla kuormitusasteella, mutta jos ne mitoitetaan reilusti yli todellisen kuorman ja toimivat 10–20 % kuormalla, hyötysuhde putoaa selvästi. Tämän vuoksi ylimitotus ”varmuuden vuoksi” on energianäkökulmasta haitallista – jokaista turhaan hankittua megawattia kohden maksetaan paitsi laiteinvestointi, myös jatkuva häviösähkö. Ratkaisuna on mitoittaa liittymä- ja UPS-kapasiteetit realistisen kuormahuipun mukaan ja hyödyntää modulaarisia ratkaisuja, joita voidaan laajentaa tarpeen kasvaessa【18】. Myös varmistusperiaate vaikuttaa häviöihin: N+1- tai 2N-konfiguraatioissa osa laitteista käy tyhjäkuormalla varmistaen toisiaan, mikä heikentää kokonaishyötysuhdetta erityisesti matalilla käyttöasteilla. Tämä kompromissi tulee tehdä tietoisesti ja vaikutukset tuoda esiin mittareilla (esim. vertailemalla PUE-arvoa täydessä kuormassa vs. osakuormalla). Vihreä sähköinfrastruktuuri tavoittelee optimaalista balanssia käytettävyyden ja energiatehokkuuden välillä – esimerkiksi hyödyntämällä uusia teknologioita kuten DC-jakelua tai synkronikoneettomia UPS-ratkaisuja, tai ottamalla käyttöön akkuvarastot tasaamaan kuormahuippuja

.

(Keskeisiä lähteitä: Geng (2015) tarjoaa kattavan yleiskuvan sähköinfran suunnittelusta ja sen tehokkuuden parantamisesta【2】.)
3.3 Jäähdytys ja lämpötilanhallinta

Tavoite: Poistaa IT-laitteiden tuottama lämpö mahdollisimman energiatehokkaasti ja hyödyntää ympäristön viileys maksimaalisesti.

Jäähdytys on datakeskuksen energiankulutuksen suurimpia yksittäisiä tekijöitä. Perinteisesti laitetilojen lämpötilat pidettiin melko alhaisina ja kosteus kontrolloituna kapealla alueella, mikä johti suureen jäähdytysenergian kulutukseen. Nykyisin ASHRAE on laajentanut suositeltuja lämpötila- ja kosteusaluita datakeskuksille, mikä mahdollistaa korkeammat lämpötilat laitetiloissa turvallisesti【22】. Tämä on tehnyt vapaajäähdytyksestä (free cooling) helpommin hyödynnettävää ympäri vuoden monilla ilmastovyöhykkeillä. Vihreässä datakeskuksessa pyritään suunnittelemaan jäähdytysjärjestelmä, joka hyödyntää mahdollisimman paljon ulkoilmaa tai muuta ilmaista jäähdytyslähdettä, ja turvautuu mekaaniseen jäähdytykseen (kompressorikoneikot, chillers) vain silloin kun välttämätöntä. Esimerkkejä energiatehokkaista jäähdytysratkaisuista ovat: kuuma- ja kylmäkäytäväerottelu ilmankierron optimoimiseksi, adiabaattinen jäähdytys (ilman kosteuttaminen), kaksifaasiset jäähdytysjärjestelmät (esim. nestejäähdytys suoraan palvelimille tai upotusjäähdytys) sekä älykäs automaatio, joka säätää puhaltimien ja pumppujen nopeuksia kuorman mukaan. Jäähdytyksen tehokkuutta mitataan mm. suhdeluvulla Power Utilization Efficiency, PUE (ks. luku 7), joka kertoo kokonaiskulutuksen ja IT-kulutuksen suhteen – hyvä jäähdytysratkaisu pitää jäähdytyksen osuuden mahdollisimman pienenä (lähellä PUE = 1,0)【23】. Operoinnin aikana jatkuva seuranta on tärkeää: esimerkiksi tuloilman lämpötilaa voidaan nostaa asteittain ja seurata vaikutusta IT-laitteiden suorituskykyyn, tai ilmavirtoja voidaan säätää havaittujen hot spottien perusteella. Ympäristön olosuhteet on myös huomioitava: esim. hellehuippuina ajoittain korkeampi PUE on hyväksyttävää, jos suurimman osan vuotta voidaan toimia vapaajäähdytyksellä ja säästää energiaa. Osakuormakäyttäytyminen on jäähdytyksessä tärkeä näkökulma – laitteiden hyötysuhde on yleensä paras nimellisellä kuormalla, ja hyvin kevyellä kuormalla esimerkiksi kompressorien COP (Coefficient of Performance) heikkenee. Tästä syystä modulaariset, skaalautuvat jäähdytysyksiköt, joita voidaan kytkeä pois päältä kuorman laskiessa, ovat suositeltavia.

(Keskeisiä lähteitä: ASHRAEn datakeskusohjeet antavat tarkat lämpötila- ja kosteussuositukset eri laitetasoille【22】, ja Geng (2015) käsittelee eri jäähdytysarkkitehtuurien hyötyjä ja haittoja【2】.)
3.4 Hukkalämpö ja energiankierrätys

Tavoite: Vähentää hukkaan menevän energian osuutta hyödyntämällä datakeskuksen tuottama lämpö.

Kaikki datakeskukseen syötetty sähkö muuttuu lopulta lämmöksi. Perinteisesti tämä lämpö on hukkavirta, joka poistetaan ilmaan tai veteen ja jää hyödyntämättä. Vihreässä datakeskuksessa tavoite on kytkeä tämä lämpö osaksi laajempaa energiajärjestelmää, esimerkiksi kaukolämpöverkkoa tai teollisuusprosesseja【20】. Käytännössä hukkalämmön hyödyntäminen vaatii sekä teknisen että taloudellisen tarkastelun: lämpö pitää kerätä (esim. nestekierto vaihtimilla), mahdollisesti lämpöpumppujen avulla nostaa lämpötila käyttökohteen vaatimuksiin, ja syöttää vastaanottavan verkon tai prosessin piiriin. Lisäksi tarvitaan sopimus hukkalämmön myymisestä tai luovuttamisesta – vastuukysymykset (kuka omistaa lämmön, kuka vastaa toimitusvarmuudesta) on määriteltävä. Suomessa kaukolämpöyhtiöt ovat kiinnostuneita datakeskusten lämmöstä: esimerkiksi Fortumin ja Microsoftin hanke Espoossa liittää suuren datakeskuksen hukkalämmön osaksi pääkaupunkiseudun kaukolämpöverkkoa

【24】. Samoin Google on toteuttamassa Haminan datakeskuksessaan lämmöntalteenottoa paikalliseen verkkoon yhteistyössä energia-yhtiön kanssa【24】. Nämä hankkeet osoittavat, että hukkalämmön hyödyntämisellä voidaan korvata fossiilisia polttoaineita kaukolämmön tuotannossa ja siten vähentää kokonaispäästöjä. Datakeskuksen suunnittelussa kannattaakin mahdollisuuksien mukaan varautua hukkalämmön talteenottoon – ainakin jättämällä tekninen valmius (esim. tilavaraukset lämmönvaihtimille). Energiankierrätyksen onnistuminen riippuu paljon sijainnista (kuten edellä käsiteltiin), mutta myös tahdosta sopia win-win-malleja energiayhtiöiden kanssa. Energy Reuse Factor (ERF) -mittari kuvaa, kuinka suuren osan datakeskuksen käyttämästä energiasta hyödynnetään uudelleen muualla【27】 (ks. luku 7).
3.5 Mittarit ja seuranta

Tavoite: Mahdollistaa datakeskuksen suorituskyvyn ja tehokkuuden läpinäkyvä seuranta ja jatkuva parantaminen.

Vihreän datakeskuksen ytimessä on mittaaminen: “You cannot improve what you do not measure.” Keskeisiä mittareita käsitellään tarkemmin luvussa 7, mutta jo suunnitteluvaiheessa tulee päättää, miten esimerkiksi sähkönkulutus, lämpötilat, käyttöasteet ja ympäristöparametrit kerätään talteen. DCIM-järjestelmät (Data Center Infrastructure Management) yhdistettynä automaatiojärjestelmiin (BMS) tarjoavat reaaliaikaisen näkyvyyden laitteiden tilaan ja energiankulutukseen. Vihreässä operoinnissa tavoitteena on luoda dashboardit tai raportit, joista voidaan säännöllisesti seurata ainakin: kokonaiskulutus vs. IT-kulutus, PUE:n kehitys, uusiutuvan energian osuus kulutuksesta, hukkalämmön määrä (MWh) toimitettuna sekä hiilidioksidipäästöt (esim. kgCO₂ per kuukausi)【20】. Jotta eri mittareiden tiedot ovat vertailukelpoisia, on määriteltävä tarkasti mittausrajat ja laskentakaavat (esim. PUE:n laskenta standardin ISO/IEC 30134-2 mukaan【23】). Mittaustiedot tulee myös tallentaa riittävällä aikaresoluutiolla (esim. 15 min tai tuntidata), jotta kuormaprofiilien muutoksia voidaan analysoida. Automaattinen hälytys poikkeamista (esim. PUE nousee yli tavoitteen tai jokin laite vikaantuu ja nostaa lämpötilaa) on tärkeä osa monitorointia, jotta ongelmiin voidaan puuttua ajoissa. Lopuksi, mittaamisen hyödyt realisoituvat vasta analytiikan ja toiminnan muutoksen kautta: dataa on hyödynnettävä säännöllisissä katselmoinneissa, joissa pohditaan mistä poikkeamat johtuvat ja mitä optimointia voitaisiin tehdä. Tästä muodostuu edellä mainittu jatkuvan parantamisen sykli.

(Keskeisiä lähteitä: Barroso ym. (2022) korostavat mittaroinnin merkitystä osana warehouse-scale-ajattelua【11】; Bilal ym. (2014) esittävät kattavan katsauksen verkon energiatehokkuusmittareista ja -taktiikoista【12】.)
P4 – Datakeskuksen elinkaaren vaiheet

Datakeskuksen suunnittelu- ja rakennusprojekti jakautuu useisiin vaiheisiin, joista jokaisessa on omat tavoitteensa ja vihreät painopisteensä. Ympäristövaikutusten minimointi edellyttää elinkaariajattelua – huomioidaan hankkeen vaikutukset alusta loppuun saakka【19】. Alla käsitellään lyhyesti kunkin vaiheen perusasiat ja tuotokset. (Monet alan best practice -ohjeet, kuten Schneider Electricin white paper【18】 ja LBNL:n Data Center Best Practices【20】, tarjoavat laajempia tarkistuslistoja elinkaaren hallintaan.)
4.1 Suunnittelu ja esiselvitys

Tavoite: Määritellä datakeskushankkeen visio, vaatimukset ja tavoitteet sekä varmistaa toteutettavuus. Tässä vaiheessa päätetään hankkeen laajuus (kapasiteetti, sijainti, budjetti) ja asetetaan konkreettiset KPI-tavoitteet vihreyden osalta (esim. PUE-arvo, uusiutuvan käyttöaste, lämpöjen hyödyntäminen). Suunnitteluvaiheessa tehdään myös tarvittavat esiselvitykset: sijaintivertailu (luku 2), alustava kapasiteettimitoitus ja arkkitehtuurisuunnitelma (IT ja infra), riskianalyysi sekä kustannusarvio. Ympäristönäkökulmasta kriittistä on sisällyttää tavoitteisiin energiatehokkuus ja päästöjen minimointi alusta alkaen – esim. määrittää, että datakeskus suunnitellaan “Energy Efficiency Directive” -yhteensopivaksi ja varustetaan mittareilla, ja että toteutusvaihtoehtoja verrataan myös elinkaaren hiilijalanjäljen perusteella【19】. Keskeiset tuotokset: projektisuunnitelma, tarvemäärittelydokumentti (sis. palvelutaso- ja kapasiteettivaatimukset), sijaintipäätös perusteluineen, sekä listaus vihreistä tavoitteista ja mittareista joita hankkeessa seurataan. On suositeltavaa laatia myös omistajan vaatimusmäärittely (Owner’s Requirements), jossa vihreät tavoitteet on kirjattu yhtä lailla kuin tekniset vaatimukset – näin ne siirtyvät suunnittelijoille ja toimittajille hankinnan edetessä.
4.2 Suunnittelu- ja hankintavaihe

Tavoite: Tuottaa yksityiskohtaiset suunnitelmat (rakennus, sähkö, jäähdytys, verkko, automaatio) ja kilpailuttaa sekä valita toimittajat. Tässä vaiheessa varmistetaan, että vihreät tavoitteet toteutuvat suunnitelmissa: esim. suunnitelmadokumentteihin (Blueprints, Basis of Design) sisällytetään vaaditut mittauspisteet, energiatehokkuustavoitteet ja materiaalivalinnat. On tärkeää, että suunnitteludokumentaatio on niin tarkka, että se toimii myöhemmin toimeksiantona rakentajille ja operaattoreille – ts. suunnitelmista tulee datakeskuksen “totuus”, johon toteutusta verrataan

【18】. Tässä vaiheessa päätetään myös laitehankinnoista: palvelinten ja muun IT-laitteiston energiatehokkuus (esim. valitaanko high-efficiency power supply -malleja), UPS-järjestelmän tyyppi (double-conversion vs. ECO-mode), jäähdytyslaitteiden mitoitus, jne. Tarjouspyyntöasiakirjoissa ja sopimuksissa kannattaa vaatia toimittajilta tietoja laitteiden tehokkuudesta eri kuormitusasteilla sekä mahdollisuuksista energiansäästötoimintoihin. Keskeiset tuotokset: täydellinen suunnitteludokumentaatio (rakennus- ja järjestelmäkuvat, kapasiteettilaskelmat, kaaviot), hankintasopimukset keskeisistä järjestelmistä. Vihreän suunnittelun varmistamiseksi hyvä käytäntö on suorittaa suunnitelmille ulkopuolinen tarkastus (esim. sertifiointikonsultti tai energiatehokkuusasiantuntija) ennen rakentamisen aloitusta, jotta mahdolliset heikot kohdat voidaan korjata suunnitelmatasolla.
4.3 Rakentaminen ja käyttöönotto

Tavoite: Rakentaa suunnitelmien mukainen datakeskus ja varmistaa, että se toimii suunnitellulla tavalla ennen tuotantokäyttöä. Rakennusvaiheessa vihreän hankkeen kannalta tärkeää on laadunvarmistus: asennusten tulee vastata suunnitelmia (esim. oikeat mittauslaitteet on asennettu oikeisiin pisteisiin, lämpöeristykset ja tiivistykset on tehty energiahävikin minimoimiseksi, kaapeloinnit on toteutettu häiriösuojatusti jne.). Ennen käyttöönottoa suoritetaan järjestelmätestaukset ja koekäytöt (commissioning). Erityisesti varmennetaan, että automaatio toimii oletetusti: esimerkiksi että hälytykset laukeavat raja-arvoissa, UPS siirtyy akkotoiminnolle moitteetta, ja jäähdytys pystyy ylläpitämään lämpötilat design-kuormalla. “As-built”-dokumentaatio on tärkeää päivittää – käytännössä toteutus poikkeaa aina jossain määrin alkuperäisistä suunnitelmista, ja ajantasaiset piirustukset sekä laitelistat luovat perustan operoinnin aikaiselle tehokkaalle hallinnalle. Mikäli rakennusvaiheessa oikaistaan tai jätetään esimerkiksi mittalaitteita asentamatta, operointivaiheessa ollaan “sokkona” eikä vihreitä tavoitteita voida todentaa

. Siksi on kriittistä, että projektin johto ei tingi vihreistä vaatimuksista kustannuspaineen alla – esim. mittaus- ja automaatiojärjestelmä on joskus helppo nähdä ylimääräisenä kustannuksena, mutta sen puute tekee datakeskuksesta mustan laatikon. Keskeiset tuotokset: valmis datakeskusympäristö laitteineen, testausraportit (esim. lämpökuormatestit täydellä keinokuormalla, varavoimakoe, verkon failover-testit), hyväksytty käyttöönotto (Commissioning-hyväksyntä) sekä päivitetty dokumentaatio.
4.4 Operointi ja ylläpito

Tavoite: Pyörittää datakeskusta tehokkaasti ja turvallisesti, täyttäen palvelutasot ja jatkaen jatkuvaa optimointia. Operointivaihe kattaa mahdollisesti kymmeniä vuosia, joiden aikana sekä IT-kuorma että teknologia kehittyvät. Vihreän datakeskuksen operoinnissa olennaista on aktiivinen monitorointi (ks. luku 5) ja ennakoiva ylläpito. Mittareita seurataan esimerkiksi kuukausittain: saavutetaanko asetetut PUE-, CUE- ym. tavoitteet, ja jos ei, niin tutkitaan syyt. Ylläpidossa pyritään pitämään laitteet valmistajien suositusten mukaisesti huollettuina, koska huollon laiminlyönti voi heikentää energiatehokkuutta (esim. likaiset ilmansuodattimet lisäävät puhaltimien energiankulutusta). Vikojen hallinta: häiriötilanteista otetaan opiksi – esim. jos jäähdytysjärjestelmässä ilmeni yllättävä ylikuumenemistilanne, analysoidaan mitä voidaan muuttaa, jottei vastaava toistu (parannetaanko hälytystasoja, lisätäänkö redundanssia tms.). Operoinnin aikana tulee myös päivittää raportteja sidosryhmille (esim. yrityksen sisäinen vuosiraportti datakeskuksen energiankulutuksesta ja päästöistä). Moderni trendi on integroida datakeskuksen ohjaus laajempaan IT-orkestrointiin: esimerkiksi kuormanjako useiden datakeskusten välillä voi tapahtua sähkön hinnan tai hiilijalanjäljen perusteella automaattisesti (jos yrityksellä on useita konesaleja). Tämä vaatii sekä sopivaa ohjelmistoalustaa että päätöksentekologiikkaa, mutta voi tuoda merkittäviä säästöjä. Operointivaiheessa vihreys “rapautuu” helposti, jos jatkuvaa seurantaa ja optimointia ei resursoida – siksi on suositeltavaa, että organisaatiossa nimetään vastuuhenkilö tai tiimi datakeskuksen energiatehokkuudelle ja ympäristöasioille, ja että heillä on käytössään selkeät mittarit ja valtuudet ehdottaa parannuksia.
4.5 Käytönaikaiset muutokset ja laajennukset

Tavoite: Toteuttaa muutokset (esim. laajennus uuteen halliin, kapasiteetin nosto, laitepäivitykset) hallitusti ja energiatehokkuus huomioiden. Suuren datakeskuksen elinkaaren aikana lähes väistämättä tehdään laajennuksia tai muutoksia. Hyvä käytäntö on soveltaa Muutoshallintaprosessia (Change Management), jossa jokainen muutos ehdotetaan, arvioidaan vaikutuksiltaan (myös energiamielessä) ja hyväksytään ennen toteutusta. Jos esimerkiksi lisätään 10 uutta räkkiä palvelimia, arvioidaan etukäteen niiden vaikutus sähkönkulutukseen, jäähdytykseen ja PUE:hen – ja varmistetaan että infrastruktuurissa on kapasiteettia (”capacity management”). Vihreä näkemys suosii modulaarisuutta: laajennukset pyritään tekemään modulaarisesti niin, että tarvittavat laitteet lisätään vasta kun oikeasti tarvitaan, eikä ylimääräistä kapasiteettia seisoteta turhaan. Lisäksi on tärkeää säilyttää läpinäkyvyys: jokainen laajennus tulisi dokumentoida (päivitetään yksiviivakaaviot, IP-laiterekisterit, kuormituslaskelmat). Käytönaikaisissa muutoksissa riskinä on, että alkuperäinen huolellinen suunnittelutyö vesittyy – esimerkiksi jos lisätään uusi laitetila ilman, että sen vaikutuksia PUE:hen tai ilmavirtaukseen analysoidaan, voidaan vahingossa heikentää datakeskuksen tehokkuutta. Tämän välttämiseksi jokainen muutos olisi hyvä tarkastella myös ”vihreän tiimin” toimesta. Yksi keino on pitää päivitettyä mallia datakeskuksesta (esim. CFD-malli ilmavirtauksista tai simulointimalli energiankulutuksesta), jota päivitetään muutosten myötä. Näin pystytään ennakoimaan vaikutukset ja pitämään optimointi hallinnassa.
4.6 Käytöstäpoisto ja uudelleenkäyttö

Tavoite: Hoitaa datakeskuksen elinkaaren loppu ympäristövastuullisesti ja tietoturvallisesti. Elinkaaren loppu kattaa tilanteet, joissa datakeskus suljetaan tai laitteita poistetaan käytöstä. Vihreyden uskottavuus voi kärsiä, jos purku- ja e-jäte hoidetaan huonosti – esimerkiksi energiatehokkaasti pyörineen datakeskuksen laitteita ei kierrätetä, vaan ne päätyvät kaatopaikalle. Siksi eikäytön hallinta on olennainen osa vihreää strategiaa【15】【16】【17】.

Mitä tehdään: Poistettaville laitteille laaditaan suunnitelma ennen sulkemista. Tähän kuuluu media sanitization eli tallennuslaitteiden tyhjennys/hävitys NIST 800-88 -ohjeiden mukaisesti tietoturvan takaamiseksi【14】. Lisäksi tehdään päätös, mitkä laitteet voidaan uudelleenkäyttää muualla (toissijaisissa tehtävissä, myydä eteenpäin) ja mitkä kierrätetään materiaalina. Kaikille jätteille (sähkö- ja elektroniikkaromu, paristot, akut, kaapelointimateriaalit, jäähdytysnesteet) valitaan asianmukaiset käsittelykanavat – yleensä sertifioidut e-jätteen kierrättäjät, jotka pystyvät talteenottamaan arvokkaat metallit ja käsittelemään haitalliset aineet oikein【15】【16】. Hankkeen lopuksi on hyvä kerätä opit: mikä toimi hyvin ja mikä huonosti koko datakeskuksen elinkaaren aikana, ja dokumentoida ne organisaation tietoon (syöte seuraaviin hankkeisiin)【17】.

Jos vaihe ohitetaan tai tehdään puutteellisesti: Riskinä on vakavia tietoturvauhkia (jos tallenteita ei tuhotakaan kunnolla, luottamuksellista dataa voi vuotaa). Ympäristön kannalta e-jätteen epäasianmukainen käsittely aiheuttaa vastuullisuus- ja lakiriskejä – elektroniikkajäte sisältää raskasmetalleja ja muita aineita, joita ei saa päätyä luontoon【16】. Mainehaitta on myös merkittävä: yrityksen “vihreä” imago voi säröillä, jos paljastuu että sen datakeskuksen laitteet dumpattiin kehitysmaahan jätteeksi. Siksi tätä vaihetta ei pidä vähätellä, vaan resursoida asiallisesti.

Tiivis "vihreän onnistumisen" sääntö: Jotta vihreä datakeskushanke onnistuu tavoitteissaan, voidaan elinkaaren läpi seurata muutamaa keskeistä periaatetta

:

    Määritä KPI:t ja mittausrajat esiselvityksessä → Ne ohjaavat kaikkea jatkosuunnittelua【19】【20】. (Esim. tavoite PUE, uusiutuvan osuus, raportoinnin kattavuus.)

    Suunnittelussa tee dokumenteista rakentamisen "totuus" → Varmista, että Basis of Design ym. dokumentit sisältävät energiatehokkuus- ja mittausvaatimukset, jotka sitten toteutetaan käytännössä【18】【20】.

    Rakentamisessa varmista toteuma + testaus → Muutoin operointi on sokkona. (Eli commissioning kunnolla: mittarit, automaatio, as-built paikoilleen, muuten vihreät tavoitteet eivät ole todennettavissa)【20】【10】.

    Operoinnissa optimoi jatkuvasti → Muuten vihreys rapautuu ajan myötä. (Ota käyttöön jatkuvan parantamisen malli ja pidä se elävänä rutiinina)【20】【13】【10】.

(Yllä viitatut [20] LBNL ja [13] Oró ym. sisältävät yksityiskohtaisia strategioita energiatehokkuuden parantamiseen datakeskuksen eri elinkaaren vaiheissa.)
P5 – Datakeskuksen toiminta vaiheittain – sähköstä palveluksi ja takaisin lämmöksi

Tässä luvussa kuvataan datakeskuksen toiminta ketjuna, jossa syötettävä sähkö ja saapuvat palvelupyynnöt kytkeytyvät IT-laitteiden laskentaan, siitä syntyvään lämpöön ja edelleen mahdolliseen hukkalämmön hyödyntämiseen. Kuvauksen tavoitteena on havainnollistaa, miten sähkö muuttuu IT-palveluksi ja käytännössä lopulta lämmöksi – sekä miten tämä prosessi voidaan valjastaa tehokkaaksi ja ympäristöystävälliseksi. Samalla tuodaan esiin, miten jatkuva mittaus ja optimointi nivoutuvat jokaiseen vaiheeseen ohjaus- ja raportointikäytänteiden kautta【13】【7】.

Rakenteellisesti käsitellään ensin kolme peräkkäistä päävaihetta: (1) sähkönsyöttö ja jäähdytys, (2) verkkopalvelupyynnöt ja (3) palvelimet ja lämmöntuotanto. Tämän jälkeen tarkastellaan hukkalämmön hyödyntämistä sekä esitellään mittaamisen ja jatkuvan parantamisen toimintamalli osana ketjua.

(Viitteet: Luvun sisältö nojaa mm. Jin ym. (2016) vihreän datakeskuksen viitekehykseen【3】 sekä Geng (2015) käsikirjan esittämään kokonaismalliin【2】.)
5.1 Vaihe 1: Sähkönsyöttö ja jäähdytys
5.1.1 Sähkönsyöttö ja jakelujärjestelmä (verkosta IT-kuormaan)

Datakeskuksen sähköjärjestelmä alkaa sähkönsyötöstä ja päättyy IT-laitteisiin. Vaiheeseen kuuluu sähköverkosta tuleva syöttö, muuntajat, mahdolliset kytkinlaitteistot, UPS-laitteisto sekä jakelukiskot tai PDU-yksiköt, joista räkit ja laitteet saavat virtansa. Tämän ketjun tehtävänä on varmistaa, että IT-laitteille on jatkuvasti riittävästi ja laadukasta sähköä. Käytettävyys (availability) on varmistettu esimerkiksi redundanteilla syötöillä ja UPSilla, mutta samalla on huolehdittava että jokainen komponentti on tehokas – muuntajien hyötysuhde, UPS:in tehokkuus eri kuormilla, ja johtimien häviöt on optimoitava. Suomen olosuhteissa sähkönjakelun erityispiirre on korkea verkon luotettavuus: kantaverkkoyhtiö Fingrid ylläpitää vakaan siirtoverkon, ja monilla alueilla on mahdollista saada kahdennettu syöttö. Tämä luo hyvän pohjan vihreälle toteutukselle, kunhan hyödynnetään mahdollisuus syöttää verkosta suoraan laitteille aina kun mahdollista (UPS asetetaan esim. bypass-tilaan normaalisti) ja käytetään akkuvarmennusta vain häiriöiden aikana. Vaihe 1:n lopputuloksena on, että sähkö on saatu turvallisesti ja mahdollisimman pienin häviöin perille IT-laitteille.

    Vaiheen 1 tuotokset:

        Sähköarkkitehtuuri ja varmistusratkaisut: dokumentoituna esim. yksiviivakaaviona (single line diagram), josta käy ilmi syöttöjen lukumäärä, muuntajat, UPS/generaattorit ja jakelun rakenne

. Tähän liittyy myös varmistusluokka (N, N+1, 2N).

Mittauspistekartta sähkölle: määriteltynä, mistä pisteistä energiankulutus mitataan. Esimerkiksi: kokonaiskulutus mitataan pääkeskuksen syötöstä (grid-in), UPS-häviöt mittaamalla UPS sisään- ja ulostulo, jakeluhäviöt mittaamalla PDU-taso. Näillä saadaan eroteltua IT-energia ja häviöt raporteissa

.

Raportointiperiaatteet energialle: päätettynä miten sähkön alkuperä ja kulutus raportoidaan. Esimerkiksi kirjataan, että ostosähkön alkuperä todennetaan alkuperätakuilla vuosittain ja raportoidaan erikseen uusiutuvan osuus sekä hiilidioksidiepäästöt (Scope 2) standardin mukaisesti

        .

    Mistä nämä tiedot saa?

        Sähkösuunnittelijalta, urakoitsijalta tai datakeskusoperaattorin teknisestä dokumentaatiosta. Mittauspisteiden määrittelyyn osallistuu DCIM/BMS-järjestelmän toimittaja/integroija. Sähkön alkuperän todentamiseen tuottaa tietoa sähkön toimittaja (esim. sertifikaatit uusiutuvasta sähköstä) ja/tai yrityksen sustainability-tiimi

        .

    Minimissään varmistettava:

        Mitataan vähintään kokonaisenergiankulutus ja IT-energiankulutus erikseen, sekä UPSin sisään/ulos-energiat, jotta häviöt voidaan laskea. Tämä muodostaa perustan PUE-luvulle ja energian kohdistamiselle

        .

    Jos vaihe tehdään puutteellisesti:

        Jos IT- ja infrastruktuurienergia sekoittuvat mittauksissa (eli ei erotella, mistä kulutus muodostuu), raportointi ja optimointi perustuvat arvauksiin. Energiankulutuksen häviökohtia ei tunnisteta ilman mittausta

        . Pahimmillaan datakeskus voi vaikuttaa tehokkaalta paperilla, mutta todellisuudessa iso osa energiasta katoaa jakeluhäviöihin tai tyhjäkäyntiin, kun sitä ei ole tehty näkyväksi.

5.1.2 Jäähdytys ja lämpötilanhallinta (sähkö → lämpö)

IT-laitteiden käyttämä sähkö muuttuu lämmöksi, joka on hallittava jäähdytysjärjestelmällä. Vaihe 1:n lopussa IT-laitteet tuottavat lämpökuorman Q_th(t), jonka poistaminen on jäähdytyksen tehtävä. Jäähdytysratkaisut vaihtelevat: yleisiä ovat ilmanjäähdytys (CRAC/CRAH-yksiköt, kylmä/kuumakäytäväerotus) ja nestejäähdytys (esim. kylmä vesi heat exchangereille, tai suora nestejäähdytys palvelimille). Monissa nykydatakeskuksissa hyödynnetään ulkoilmaa niin paljon kuin mahdollista – eli vapaajäähdytystä silloin kun ulkolämpötila sen sallii. Jäähdytyksen energiankulutusta kuvaa usein PUE-komponentti: kuinka monta wattia jäähdytykseen kuluu per IT-watti. Hyvä suunnittelu pyrkii PUE:n jäähdytyskomponentissa < 0,2 tasoon (eli <20% lisäkulutus). Operoinnissa ohjauslogiikalla on suuri merkitys: jäähdytysjärjestelmä voidaan säätää reagoimaan IT-kuormaan – esimerkiksi nostaa jäähdytyskoneiden käyntiä vain kuumimpina tunteina ja muuten pyörittää vapaajäähdytystä. Osakuormakäyttäytyminen korostuu myös: jos datakeskus pyörii puolityhjänä, jäähdytyslaitteetkin voivat olla ylimitoitettuja ja käydä tehottomasti. Siksi modulaarisuus on tärkeää: useita pieniä chiller-yksiköitä, joista vain tarvittava määrä on päällä, tai useita tuulettimia, joita voidaan sammuttaa osan ajasta. On myös erotettava jäähdytyksen mittaus omaksi kokonaisuudekseen: datakeskuksen energiatehokkuuden kannalta on hyödyllistä mitata erikseen jäähdytyksen kulutus (kWh) ja verrata sitä IT-kulutukseen – tästä saadaan suoraan PUE:n dynamiikka. Samoin lämpötiloja tulee mitata laitetilassa (esim. ylä- ja alarivissä, kuuma- ja kylmäkäytävissä) sekä nestevirtauksia, jos käytössä on vesikierto. Näiden mittausten avulla tunnistetaan mahdolliset ongelmakohdat (esim. ylikuumenemiset tai ylimitoitetut virtausasetukset).

    Vaiheen 2 tuotokset:

        Jäähdytysjärjestelmän kuvaus ja ohjausperiaatteet: dokumentoituna esim. kaaviona, josta ilmenee ilmankierto tai vesikierto, laitteiden sijoittelu ja ohjauslogiikan pääpiirteet (asetuspisteet, milloin mikäkin yksikkö käynnistyy)

.

Mittauspisteet jäähdytykselle: päätettynä ja toteutettuna: esim. sähkömittaus jokaiselle chillerille/pumpulle/puhaltimelle, lämpötila-anturit sisään- ja poistoilmalle, sekä mahdolliset ilmavirran tai vesivirtauksen mittaukset. Näin saadaan dataa jäähdytyksen tehokkuuden laskentaan (esim. kuinka COP kehittyy kuormituksen mukaan)

.

Dokumentoidut asetukset: käyttöönoton yhteydessä laadittu lista asetuksista (lämpötilan asetuspiste, humidex-rajat, paine-erot yms.), jotka on valittu datan perusteella. Näin myöhemmin voidaan seurata, jos asetuksia muutetaan, miten se vaikuttaa mittareihin

        .

    Mistä nämä tiedot saa?

        LVI/HVAC-suunnittelijalta sekä automaatiointegraattorilta (BMS/DCIM). Commissioning-prosessin kautta varmistetaan, että asetukset on dokumentoitu ja testattu. Esim. laitevalmistajien datasheetit antavat referenssit: kuinka chillerin COP riippuu ulkolämpötilasta, tms., joiden pohjalta ohjaus on viritetty

        .

    Minimissään varmistettava:

        Lämpötilojen seuranta kriittisissä pisteissä (tuloilma IT-laitteille, kuuman ilman paluukanava) ja jäähdytyksen sähkönkulutuksen mittaus. Ilman näitä jäähdytyksen optimointi on hankalaa, koska ei tiedetä onko jäähdytyksen osuus 10 % vai 50 % kokonaiskulutuksesta eikä missä olosuhteissa muutos tapahtuu

        .

    Jos vaihe tehdään puutteellisesti:

        Jäähdytys jää “muu kuorma” -kategoriaan eikä sen vaikutusta voida erottaa. Tällöin esimerkiksi PUE-luku voi vaihdella, mutta ei tiedetä johtuuko se IT-kuormasta vai jäähdytyksen muutoksista. Ilman erillistä mittausta ja säätömahdollisuutta jäähdytyksen asetuspisteisiin, datakeskuksen lämpötilaa ei uskalleta nostaa optimoinnin vuoksi, koska vaikutusta ei voida todentaa – jäädään konservatiivisiin, ehkä liian alhaisiin lämpötiloihin ja hukataan energiansäästömahdollisuus

        .

5.2 Vaihe 2: Verkkopalvelupyynnöt ja tietoliikenne
5.2.1 Verkkoyhteydet (palvelu → liikenne → energiankulutus)

Käyttäjien palvelupyynnöt kulkevat datakeskukseen verkon kautta: internet-yhteydet, operaattorien runkoyhteydet ja kampusverkot ohjaavat liikenteen palvelimille. Verkkoinfrastruktuuriin kuuluu reitittimet, kytkimet, palomuurit ja muut laitteet, jotka kuluttavat nekin sähköä ja tuottavat lämpöä. Verkkoarkkitehtuurin suunnittelussa on huomioitu redundanssi (varmistetut reitit, useampi operaattori), mutta vihreä näkökulma tuo lisäfokuksen: verkon laitteiden käyttöaste ja energiatehokkuus. Tyypillisesti verkkolaitteet voivat säätää energiankulutustaan liikenteen mukaan – esimerkiksi porttien virranhallinta (Ethernet Energy Efficient Ethernet -standardit) tai koko laitteen lepotila, jos liikennettä ei ole. Datakeskuksen sisäverkon topologia vaikuttaa myös: mitä lyhyemmät ja vähemmän moninkertaiset reitit, sen vähemmän hukkaenergiaa kuluu siirrossa. Modernit konesaliverkot (esim. leaf-spine-arkkitehtuuri) on usein suunniteltu suorituskyky edellä, mutta vihreässä datakeskuksessa voidaan harkita virransäästöominaisuuksia kytkimiin (esim. suljetaan osa linkkejä, jos liikenne on vähäistä yöllä). Verkon energiankulutus on toki yleensä vain muutama prosentti datakeskuksen kokonaiskulutuksesta【20】, mutta se on osa IT-kuormaa. Erityisesti, jos datakeskus tuottaa paljon sisäistä liikennettä (esim. hajautetut palvelut), verkon optimoinnilla voi olla merkitystä.

    Vaiheen 3 tuotokset:

        Verkon energiaprofiili: kuvaus verkkolaitteiden kulutuksesta suhteessa liikennemäärään. Tämä voidaan raportoida esim. watteina per Gbit/s tai havaita verkon kokonaiskulutus ajan yli ja rinnalla dataliikenteen volyymi

. Idea on tunnistaa, jääkö verkkoon paljon käyttämätöntä kapasiteettia.

Verkon mittaussuunnitelma: määriteltynä, mitä verkon osa-aluetta mitataan. Esim. päätetään mitata kokonaissähkönkulutus kytkinkohtaisesti ja yhdistää se liikennetietoihin (porttikohtaiset bit/s arvot) DCIM:ssä. Tämä mahdollistaa verkon osuuden laskemisen IT-energiasta ja tunnistaa poikkeamat (jos jokin laite alkaa kuluttaa poikkeavasti)

        .

    Mistä nämä tiedot saa?

        Verkkosuunnittelijalta ja operaattoreilta: he voivat antaa laitelistat ja tyypilliset kulutukset. Lisäksi verkon hallintajärjestelmä (NMS) tuottaa liikennetilastoja. DCIM/BMS-integraatioon voidaan liittää esimerkiksi SNMP-kyselyt kytkimien sähkönkulutuksesta (jos laitteet sitä tukevat) tai mittaus PDU-tasolla, johon kytkimet on liitetty

        .

    Minimissään varmistettava:

        Ainakin päätason (core) verkkolaitteiden sähkönkulutus mitataan kokonaisuutena. Näin tiedetään, paljonko verkko vie tehoa. Lisäksi on hyödyllistä tunnistaa liikenneprofiilit (esim. erottaa sisäisen ja ulkoisen liikenteen määrät), vaikkei suoraa energiamittausta jokaisesta portista olisikaan

        . Oleellista on, että mahdollisiin verkon laajennuksiin osataan varata oikea määrä tehoa ja jäähdytystä – tämä onnistuu, kun tunnetaan nykyverkon kulutus suhteessa kapasiteettiin.

    Jos vaihe tehdään puutteellisesti:

        Verkon energiankäyttö jää “näkymättömäksi”. Tällöin datakeskuksen energiatehokkuustoimet voivat unohtaa, että verkko saattaa kuluttaa merkittävän määrän (esim. suurissa pilvi-infrastruktuureissa verkon osuus voi olla 10 %). Ilman mittausta ja seurantaa verkon laitteiden ylimääräistä kapasiteettia ei havaita – esimerkiksi vanhoja kytkimiä voisi poistaa tai vaihtaa tehokkaampiin, jos tiedettäisiin että ne vievät paljon tehoa kevyeenkin käyttöön

        . Myös verkkovikojen vaikutus jää pimentoon energian osalta: jos jokin reitti katkeaa ja liikenne kulkee pidempää varareittiä, se saattaa lisätä latenssia ja energiankulutusta, mutta ilman näkyvyyttä sitä ei huomata.

(Huomio: Verkon optimoinnin periaatteita käsitellään syvällisemmin esimerkiksi Bilal ym. 2014 katsauksessa【12】.)
5.3 Vaihe 3: Palvelimet, tallennus ja lämmöntuotanto
5.3.1 Laskenta ja tallennus (sähkö → bittivirrat → lämpö)

Ketjun viimeisessä päävaiheessa sähkö muuttuu varsinaisiksi IT-palveluiksi: palvelimet prosessoivat dataa, tallennusjärjestelmät lukevat ja kirjoittavat biteiksi muutettua informaatiota, ja verkkolaitteet ohjaavat tuloksia takaisin käyttäjille. Samalla prosessit tuottavat lämpöä, joka on poistettava (vaihe 1). Palvelimien suorituskyky ja hyötysuhde ovat tässä keskiössä: modernit palvelinprosessorit ovat erittäin tehokkaita, mutta niiden hyödyntämisaste ratkaisee energiatehokkuuden. Korkealla käyttöasteella (esim. >50%) palvelimen tekemä työ per wattimäärä on huomattavasti suurempi kuin hyvin alhaisella käyttöasteella pyöriessä, koska pohjakulutus “hukkuu” hyötylaskennan sekaan. Siksi edellä kuvatut virtualisointi ja resurssienhallinta (3.1) ovat niin olennaisia – ne varmistavat, että tässä vaiheessa mahdollisimman vähän palvelintehoa menee hukkaan tyhjäkäynnillä. Tallennus ja muisti: Myös tallennusjärjestelmät (levyjärjestelmät, flash-muistit) kuluttavat energiaa. Vanhemmat mekaaniset levyt pyörivät jatkuvasti, mutta nykyään yleistyvät SSD-levyt ovat energiatehokkaampia ja myös lepotilassa kulutus on hyvin pientä. Datakeskuksissa on lisäksi usein muistikerroksia (cache, RAM), joiden riittävä mitoitus voi vähentää hitaille levyille tehtäviä hakuja ja siten säästää energiaa. Verkkopalvelimet ja ohjelmisto: Ohjelmistotason optimointi voi parantaa tehokkuutta – esimerkiksi välimuistit ja kuorman tasaus algoritmit voivat pienentää yksittäisten pyyntöjen käsittelyaikaa ja siten energiamäärää. Tämä on vaikeammin mitattavissa suoraan energiakuluina, mutta näkyy palvelimien käyttöasteina ja vasteaikoina.

Kaiken kaikkiaan vaihe 3 tuottaa valmiin palvelun käyttäjälle (vastauksena hänen palvelupyyntöönsä). Samalla syntyy lämpöä suunnilleen yhtä paljon kuin IT-laitteet ottivat sähkötehoa. Tämä lämpöenergia on datakeskuksen “lopputuote” sähkö- ja ympäristönäkökulmasta – valitettavasti sitä ei yleensä voida hyödyntää datakeskuksen sisällä (paitsi mahdollisesti toimistorakennusten lämmitykseen talvella). Se on kuitenkin potentiaalinen resurssi kaukolämpöön tai muuhun tarkoitukseen, kuten seuraavassa alaluvussa käsitellään.

    Vaiheen 3 tuotokset:

        Laskentapalvelu tuotettuna: IT-järjestelmä tuottaa halutut palvelut sovitulla palvelutasolla (esim. verkkosivut, tietokantakyselyt jne.) – tämä on tietenkin hankkeen päätavoite, mutta vihreässä hankkeessa se tehdään aiempaa energiatehokkaammin (mitattavissa esim. Wattia per transaktio -lukuna, jos halutaan).

        Lämpökuorma datakeskuksessa: määriteltynä ja mitattuna. Esim. voidaan raportoida, että datakeskus tuottaa jatkuvasti X kW lämpöä laitetilassa. Tämä arvo vastaa IT-tehoa + sähkönjakelun ja jäähdytyksen häviöitä. Tietämällä lämpökuorman suuruus ja profiili, osataan mitoittaa hukkalämpöratkaisu (jos käytössä).

    Jos vaihetta ei optimoida:

        Palvelimet voivat jäädä alikuormitetuiksi ja hukata energiaa tyhjäkäynnillä. Suuri osa sähköstä muuttuu lämmöksi, josta ei ole hyötyä – ja se pitää vieläpä jäähdyttää. Tämä on se perinteinen, vältettävä tilanne. Optimoinnilla halutaan varmistaa, että jokainen wattikulutus tuottaa mahdollisimman paljon laskentatyötä eikä ole turhaa ylivarantoa.

(Huom: Vaiheen 3 tehokkuus heijastuu suoraan mittareihin kuten PUE ja CUE – jos IT-sähköä kuluu vähemmän tietyn kuormatyön tekemiseen, myös PUE-paranee. Siksi IT-optimointi on yhtä tärkeää kuin infrastruktuurin optimointi.)
5.4 Hukkalämmön hyödyntäminen ketjussa

Tässä kohdassa ketjua tarkastellaan laajennettuna datakeskuksen ulkopuolelle: mitä tapahtuu lämpöenergioille, jotka datakeskus tuottaa? Perinteisessä ketjussa lämpö häviää ympäristöön, mutta vihreässä visiossa se pyritään ottamaan talteen (ks. 3.4). Hukkalämmön hyödyntäminen kytkee datakeskuksen osaksi energiajärjestelmää. Esimerkiksi, jos datakeskuksen jäähdytysvedestä kerätään lämpö talteen lämpöpumpulla ja syötetään kaukolämpöverkkoon, datakeskus toimii eräänlaisena pienenä lämpövoimalana. Tällä voi olla huomattava positiivinen vaikutus: se vähentää fossiilisen polttoaineen tarvetta lämmöntuotannossa ja parantaa datakeskuksen kokonaisenergian hyödyntämisastetta. Energy Reuse Factor (ERF) on mittari, joka kertoo tämän hyödynnetyn osuuden【27】. Ihannetapauksessa datakeskus voisi saavuttaa ERF = 0,5 (50 % energiasta uudelleenkäytetään). Käytännössä luku on usein alhaisempi, mutta jo 20–30 % uudelleenkäyttö on merkittävää.

Hukkalämmön hyödyntämiseen liittyy toimintamalli: datakeskuksen operoijan on tehtävä yhteistyötä lämpöverkko- tai teollisuuspartnerin kanssa. Tämä lisää hieman kompleksisuutta operointiin – esimerkiksi sovitaan veden lämpötila-alueesta ja lämmön toimitusajoista. Voi olla tarpeen säätää IT-kuormaa: jos kuormaa voidaan ajoittaa enemmän silloin kun lämmölle on kysyntää, hyödynnetään potentiaali paremmin. Kuitenkin, kaikkea kuormaa ei yleensä voi aikatauluttaa lämmön ehdoilla, sillä palvelutasot menevät edelle.

Suomessa on jo konkreettisia esimerkkejä: Helsingin seudulla Fortumin ja Microsoftin datakeskushanke integroidaan tiiviisti kaukolämpöön – tavoitteena kattaa jopa ~40 % Espoon kaukolämmön tarpeesta datakeskuksen lämmöllä【24】. Googlen Haminan datakeskuksessa puolestaan aloitetaan vuonna 2022 hukkalämmön toimitus paikalliseen verkkoon, mikä on yksi ensimmäisistä isoista toteutuksista Suomessa【26】. Nämä hankkeet osoittavat suunnan: tulevaisuudessa datakeskusten lämpöä pidetään arvokkaana resurssina, ei jätteenä. Hankkeen suunnittelussa on siis syytä jo vaiheessa 1 (sijainti) miettiä hukkalämmön mahdollisuus ja vaiheessa 3 (jäähdytys) toteuttaa tekniset ratkaisut sen talteenotolle.

(Viitteet: IRENA 2021 raportti esittelee hukkalämmön hyödyntämisen mahdollisuuksia laajasti【25】; Fortumin ja Googlen tapaushankkeista on tietoa mm. yritysten julkaisuissa【24】【26】.)
5.5 Mittaaminen, analysointi ja jatkuva optimointi
5.5.1 Mittaus- ja johtamismalli

Jotta edellä kuvatun ketjun kaikki vaiheet pysyvät optimaalisina, datakeskuksen operoinnille tarvitaan mittaus- ja johtamismalli. Tämä tarkoittaa käytännössä prosessia ja työkalukokonaisuutta: mitä mitataan, miten data tallennetaan, miten siitä raportoidaan ja miten varmistetaan toiminnan jäljitettävyys (audit trail). Kuvainnollisesti voidaan esittää mittausketju: mittauspisteet → data → laskenta → raportointi → toimenpiteet

.

Datakeskuksessa tulisi mitata vähintään kokonaisenergian kulutus ja IT-energian kulutus erikseen sekä jäähdytyksen kulutus, kuten aiemmin todettu. Lisäksi voidaan mitata yksityiskohtaisemmin: hukkalämmön toimitetut MWh, palvelinkohtaisia tehoja, lämpötiloja useista pisteistä jne. Olennainen osa mallia on datan tallennus ja käsittely: yleensä kerätään jatkuvasti sensoridataa ja tallennetaan se tietokantaan. Sitten lasketaan halutut aggregaatit (esim. tunneittaiset PUE-arvot, viikkokeskiarvot) ja esitetään ne hallintapaneeleissa. Hyvä käytäntö on määritellä roolit: kenelle raportoidaan mitä. Esimerkiksi operointitiimi seuraa reaaliaikaista dashboardia (hälytykset, nykyiset PUE-arvot), kun taas johdolle menee kuukausiraportti (sisältäen trendit, saavutetaanko tavoitteet). Kaiken mittaus- ja raportointidatan tulee olla jäljitettävissä: jos arvo poikkeaa, pitää pystyä porautumaan syyhin (audit trail). Tämä tarkoittaa, että datan käsittely on dokumentoitu – esim. laskentakaavat on kirjattu (miten vaikkapa CUE lasketaan input-datasta) ja kaikki muutokset dataan (kalibroinnit, korjaukset) logitetaan.

Kun mittausmalli on paikallaan, on mahdollista toteuttaa jatkuva parantaminen. Käytännössä se voi toimia niin, että kuukausittain pidetään “tehokkuuspalaveri”, jossa käydään läpi edellisen kuukauden data: olivatko kaikki arvot tavoitealueilla, mitä poikkeamia ilmeni ja miksi. Jos esimerkiksi havaitaan, että tiettynä viikonloppuna PUE nousi huomattavasti, tutkitaan syy – oliko jokin jäähdytysyksikkö vikatilassa, tai ajoitettiinko jokin raskas kuorma? Tämän analyysin pohjalta tehdään muutos: esim. päivitetään huoltosuunnitelmaa tai ohjausasetuksia. Sitten todennetaan seuraavasta datasta, auttoiko muutos. Tätä sykliä toistetaan. Vähitellen datakeskus yleensä “vakiintuu” optimaaliselle tasolle, kun suurimmat löydetyt tehottomuudet on korjattu. Mutta ympäristö muuttuu – kuormat kasvavat, laitteita ikääntyy – joten prosessi on jatkuva.

    Mittausmallin tuotokset:

        Mittaussuunnitelma ja arkkitehtuuri: kuvattu selkeästi, miten data kulkee antureilta tallennusjärjestelmään ja siitä raportteihin

. Esim. tiedetään että mittaukset kerätään BMS:stä Modbus/OPC:n kautta tietokantaan X, josta ne haetaan dashboardille Y.

Toimintamalli jatkuvaan parantamiseen: sovittu käytännöksi – esimerkiksi dokumentoitu prosessikaavio “mittaa -> analysoi -> muutos -> todenna -> vakioi” ja nimetty vastuuhenkilöt. Tämä voidaan sisällyttää jopa organisaation laatujärjestelmään.

Minimivaatimukset: kirjattu mitä vähintään mitataan ja raportoidaan. Esimerkiksi: “Kokonaisenergia ja IT-energia eroteltuna kuukausiraportissa; jäähdytyksen energia raportoidaan osuutena; hukkalämpö MWh raportoidaan jos käytössä.” Näin varmistetaan että mikään olennainen ei jää huomiotta

        .

    Jos tämä vaihe ohitetaan:

        Ilman selkeää mittaus- ja johtamismallia vihreän datakeskuksen idea vesittyy. Vaikutuksia ei voida todentaa mittareista, päätöksenteko perustuu oletuksiin ja raportointi jää epämääräiseksi

        . Saattaa käydä niin, että aluksi asetetut KPI:t raportoidaan kerran käyttöönottovaiheessa, mutta sitten seuranta hiipuu eikä kukaan huomaa, jos tehokkuus alkaa heikentyä. Lisäksi ilman jäljitettävyyttä organisaatio ei voi oppia virheistään – esimerkiksi jos jokin muutos heikensi PUE:ta, syy jää dokumentoimatta eikä korjaavia toimia tehdä.

5.5.2 Ketjun yhteenveto

Datakeskuksen toiminta muodostuu kokonaisuudesta, jossa sähkö, IT, verkko, jäähdytys ja lämpö ovat kytkeytyneitä toisiinsa. Vihreän datakeskuksen toteutus tarkoittaa käytännössä sitä, että kaikkia näitä osa-alueita johdetaan yhtenä kokonaisuutena energiatehokkuus ja ympäristövaikutukset huomioiden. Suomalaisessa toimintaympäristössä vihreän datakeskuksen erityispiirteitä ovat yleensä: (i) uusiutuvan sähkön osuuden maksimointi ja todentaminen, (ii) IT-kuorman ohjaus kuormitushuippujen leikkaamiseksi, (iii) verkon kulutuksen seuranta osana kokonaisuutta, (iv) jäähdytyksen optimointi paikallisen ilmaston puitteissa (max vapaajäähdytys), (v) hukkalämmön syöttäminen kaukolämpöön aina kun mahdollista, sekä (vi) mittaus- ja johtamismalli, joka tuottaa jatkuvan seurannan ja todennuksen edellä mainituille

.

    Koontituotos: Vihreän datakeskuksen operoinnin malli, jossa on määritelty:

        energian mittausrajat (mitä mitataan ja mihin asti IT-energia rajataan),

        uusiutuvan energian ja päästöjen todentaminen (miten varmistetaan että ostettu sähkö on halutun mukaista ja miten päästöt lasketaan), sekä

        hukkalämmön mittaus ja toimitusmalli (jos hyödynnetään, miten MWh kirjataan ja raportoidaan)

        .

    Jos ketju jää osa-alueiksi ilman integraatiota:

        Kokonaisvaikutusta ei saada näkyviin. Energiansäästötoimet voivat jäädä osaoptimoinneiksi, jos esimerkiksi IT-tiimi optimoi palvelimiaan mutta infrastruktuuritiimi ei tiedä siitä mitään – tai päinvastoin. Ilman yhtenäistä mallia eri tiimien toimenpiteiden yhteisvaikutus voi jäädä epäselväksi, eikä datakeskuksen koko potentiaalia saada hyödynnettyä

        .

(Luvun 5 lopuksi lukijan tulisi hahmottaa “end-to-end” kuva datakeskuksesta: mistä energia tulee ja mihin se menee, ja miten joka vaiheessa voidaan saavuttaa hyötyjä. Seuraavaksi luvussa 6 pureudutaan tarkemmin energian kulutuksen jakaumiin ja hukkalämmön käsittelyyn.)
P6 – Energian kulutus ja uudelleenkäyttö

Tässä luvussa käsitellään, mistä datakeskuksen kWh-lukemat muodostuvat, miten työkuorma ja tietoliikenne näkyvät energiankulutuksessa, miten kulutus vaihtelee ajassa, mikä on jäähdytyksen rooli sekä mitä hukkalämpö tarkoittaa ja miten sitä voidaan hyödyntää. Lisäksi kuvataan, miten energiankäyttö kytketään hiilidioksidipäästöihin ja miten luvut viedään raportointiin ja tunnuslukuihin standardoidulla tavalla. (Tätä tietoa hyödynnetään myöhemmin kehittyneissä optimointimenetelmissä – ns. menetelmäopas jatkaa tästä eteenpäin.)
6.1 Peruskuva: mistä kWh:t syntyvät

Miksi? Ymmärtämällä energiankulutuksen jakautumisen voimme kohdistaa optimointitoimet oikein. kWh on energiaraportoinnin perusyksikkö, ja se kertoo kulutetun energian määrän tietyn ajan yli (teho kW integroitu ajassa). Ilman yhteistä määrittelyä siitä, mitä mitataan ja mistä mittausrajasta, eri datakeskusten tai eri kuukausien lukemat eivät ole vertailukelpoisia. Siksi on tärkeää sopia mittausrajat: yleensä datakeskuksen kokonaisenergia sisältää kaiken sähkön, joka syötetään konesali-infrastruktuuriin, ja IT-energia sisältää vain IT-laitteiden kulutuksen【20】. Tyypillisesti PUE-metriikan määrittelyssä on standardi (ISO/IEC 30134-2:2016) jonka mukaan PUE = kokonaisenergia / IT-energia tietyllä ajanjaksolla【23】. Tämä standardi määrittelee myös kategorioita, miten tarkasti mittaus tehdään (esim. jatkuva mittaus vs. kertaluonteinen). Näistä on sovittava oman datakeskuksen raportointia varten.

Mitä tehdään? Ensimmäiseksi piirretään energiakaavio eli määritetään mittausrajat ja energiavirrat:

    Sisään datakeskukseen: verkkosähkö (ja mahdollinen oma tuotanto, esim. kattoaurinkopaneelit).

    Sisäinen käyttö: jaetaan IT-laitteiden kulutus ja tukijärjestelmien kulutus. Tukijärjestelmiin kuuluvat jäähdytys, sähkönjakelun häviöt (muuntajat, UPS), valaistus, jne.

    Ulos: lämpö poistuu (lähes kaikki sähkö muuttuu lämmöksi tilassa). Mahdollinen hukkalämmön uudelleenkäyttö lasketaan ulosvirtaavana energiana. Myös häviöt voidaan mieltää ulos menneiksi (esim. UPS-häviölämpö poistuu tilasta).

Kun tämä energian tase on kuvattu, sovitaan mittaus- ja raportointitavat PUE:lle ja muille mittareille. Standardi ISO/IEC 30134-2 antaa tarkan ohjeen PUE:n laskentaan ja raportointiin – sitä kannattaa noudattaa, jotta oma datakeskus on vertailukelpoinen alan muihin【23】. Samoin jos hyödynnetään uusiutuvaa energiaa, voidaan raportoida Renewable Energy Factor (REF), joka määritellään standardissa ISO/IEC 30134-3:2016【27】. REF = uusiutuvan energian osuus kokonaisenergiankäytöstä. Tämä luku on 1,0 jos kaikki energia on uusiutuvaa (tai ostettu uusiutuvana), ja pienempi muuten. Toisin sanoen REF 0,0 tarkoittaisi täysin fossiilista sähköä.

Kun perusenergiatase on selvillä, voidaan tehdä karkea arvio jakautumisesta: esimerkiksi IEA arvioi, että tyypillisessä modernissa datakeskuksessa noin 50 % energiasta menee palvelimiin, ~10 % tallennukseen, ~10 % verkkoon ja ~30 % infrastruktuuriin (jäähdytys + muut)【20】. Tällaiset arviot auttavat tunnistamaan, mihin kannattaa panostaa – jos esimerkiksi infrastruktuuri vie 50 %, PUE on noin 2,0 mikä viittaa optimointitarpeeseen. Jos infrastruktuuri vie vain 20 %, PUE ~1,25, mikä on jo varsin hyvä. Nämä luvut on hyvä tuoda esiin projektin alussa ja seurata operoinnissa.

Tuotokset:

    Energian mittausrajakuvaus: yksinkertainen kaavio ja sanallinen määrittely, joka dokumentoidaan. Siinä esim. mainitaan: "Kokonaisenergiaksi lasketaan kaikki syöttöjen kautta tuleva sähkö (mittaus pääkeskuksella). IT-energiaksi lasketaan kaikki IT-kuormille menevä sähkö (mittaus räkki-PDU:ilta). Muihin kuormiin (Infra) jää kaikki erotus." Tämä dokumentti liitetään esim. operointikäsikirjaan.

    Mittauspiste- ja mittarilista: listaustyyppinen dokumentti kaikista energiankulutuksen mittauspisteistä ja niistä lasketuista mittareista. Esim: "M1: Pääkeskus syöttö, mitataan energiamittarilla X → KokonaiskWh. M2: UPS lähtö, mittari Y → IT-kWh. M3: Chiller sähkösyöttö, mittari Z → jäähdytyksen kWh..." jne. Tämä varmistaa, että operointivaiheessa mittaukset eivät jää epäselviksi.

    Ensimmäinen PUE-laskenta ja raportointisääntö: heti kun datakeskus on käyttöönottovaiheessa, lasketaan PUE testidatalla (esim. commissioningissa). Raportointisääntö tarkoittaa, että päätetään millä aikavälillä PUE raportoidaan (jatkuvasti dashboardilla, kuukausittain raportissa jne.) ja sisällytetäänkö siihen jotain erityistä (esim. mainitaan kategoria, jos ei mitata jatkuvasti).

(Viite: ISO 30134-2 standardi [23] on tärkeä lähde PUE:n määrittelyssä. Myös IEA:n data [19][20] antaa kontekstia energiankulutuksen osuuksista.)
6.2 Kuorman vaihtelut ja kapasiteetin vaikutus

(Tässä alaluvussa voidaan käsitellä lyhyesti, miten energiankulutus vaihtelee ajassa kuorman mukaan ja mitä vaikutusta ylimitoitetulla kapasiteetilla on.)

Datakeskuksen energiankulutus ei ole vakio, vaan seuraa yleensä IT-kuorman vaihteluja. Päiväaikaan kuorma voi olla korkeampi (käyttäjiä paljon), yöllä matalampi. Tämä näkyy IT-tehonkulutuksen vaihteluina. Jäähdytyksen kulutus usein korreloi IT-tehon kanssa, mutta joissain tilanteissa voi olla viivettä tai eroa (esim. yöaikaan ulkoilma on viileämpää → jäähdytys kuluttaa vähemmän suhteessa IT-tehoon). Vihreässä operoinnissa pyritään pitämään laitteet mahdollisimman tehokkaalla käyttöalueella myös vaihtelevalla kuormalla. Yksi keino on niin sanottu dynamic right-sizing: sammutetaan osa laitteista kevyellä kuormalla. Esimerkiksi, jos yöllä IT-kuorma on vain 30 % maksimista, voidaan osa jäähdytyskoneista ja UPS-moduuleista kytkeä lepotilaan, jolloin ne eivät lisää häviöitä. Tämä edellyttää automaatiolta kykyä havaita tilanne ja tehdä toimenpiteet.

Ylimitoitettu kapasiteetti heikentää kuormitusasteita ja usein hyötysuhteita. Esimerkiksi, jos datakeskus toimii pysyvästi vain 20 % kuormalla, monet laitteet käyvät epätehokkaalla alueella. Tämä nostaa PUE:ta ja voi myös lyhentää laitteiden elinikää (kylmäkäynnistyksiä jne.). Siksi on suositeltavaa skaalata kapasiteettia modulaarisesti: lisää kapasiteettia vasta kun kuorma kasvaa (jos mahdollista). Käytännössä toki aina on varakapasiteettia, mutta sen vaikutus pyritään minimioimaan.

(Viite: Barroso & Hölzle (2007) klassinen paperi [6] "The Case for Energy-Proportional Computing" perustelee hyvin, miksi vaihtelut ja matalat käyttöasteet ovat ongelma – ja keinoina nimenomaan skaalaus ja lepotilat.)
6.3 Hiilijalanjälki ja sähkön alkuperä

Datakeskuksen energian hiilijalanjälki riippuu suoraan sen käyttämän sähkön päästökerroista. Suomi on sitoutunut EU:n ilmastotavoitteisiin, ja energiatehokkuusdirektiivin (EED) mukaisesti suurten datakeskusten (>500 kW) on raportoitava energiankulutuksensa ja siihen liittyvät päästöt viranomaisille vuodesta 2024 alkaen【20】. Hiilijalanjälki lasketaan tyypillisesti Scope 2 -päästöinä GHG-protokollan mukaisesti: otetaan ostosähkön määrä (MWh) ja kerrotaan se sähköntuotannon päästökertoimella (kgCO₂/MWh)【21】. Yritys voi käyttää paikallista verkkosähkön keskiarvokerrointa tai markkinapohjaista kerrointa, jos se ostaa erikseen uusiutuvaa energiaa (esim. sertifikaatein). Tärkeää on läpinäkyvyys: GHG Protocol Scope 2 -ohjeistus painottaa, että jos väittää käyttävänsä 100 % vihreää sähköä, on raportoitava myös jäännösverkkojen päästöt erikseen, jotta kokonaiskuva säilyy【21】. Datakeskuksen on siis syytä pitää kirjaa sähköntoimittajan raporteista ja uusiutuvat sertifikaatit tallessa.

Carbon Usage Effectiveness (CUE) on mittari, joka ilmaisee hiilidioksidipäästöt suhteessa IT-työhön, analogisesti PUE:lle. Standardi ISO/IEC 30134-8:2022 määrittelee CUE:n laskennan【26】. Periaatteessa CUE = (kokonaispäästöt kgCO₂) / (IT-energiankulutus kWh) tietyltä ajalta. Pienempi CUE on parempi. CUE:ta voidaan parantaa kahdella tavalla: vähentämällä energiankulutusta (parempi PUE) tai käyttämällä vähäpäästöistä sähköä (pienempi päästökerroin).

Suomen kaltaisessa maassa, jossa sähkö on suhteellisen vähäpäästöistä jo nyt (paljon ydinvoimaa ja uusiutuvaa), suurin vaikutus tulee energiatehokkuudesta. Toisaalta, monet datakeskusoperaattorit ovat globaalisti luvanneet 100 % hiilineutraalin toiminnan – mikä usein tarkoittaa uusiutuvan sähkön ostoa ja mahdollisesti ylijäämäpäästöjen kompensointia. Esimerkiksi Google on asettanut tavoitteekseen käyttää hiilivapaata energiaa kaikkina tuntina vuoteen 2030 mennessä (24/7 Carbon-Free Energy). Tämä vaatii datakeskuksen sähkönkulutuksen ajoittamista silloin kun esim. tuulivoimaa on saatavilla tai varastointiratkaisuja. Tällaiset edistyneet toimet menevät perusoppaan ulkopuolelle, mutta ne mainitaan, jotta lukija tiedostaa trendin.

Yhteenveto luvusta 6: Datakeskuksen energiankulutus tulee jakaa osiin ja ymmärtää, jotta voidaan raportoida tunnusluvut (kuten PUE, REF, CUE). Uusi EU-lainsäädäntö edellyttääkin suurilta datakeskuksilta seuraavia tietoja vuosittain【20】:

    Kokonaisenergiankulutus (MWh) ja jaottelu IT vs. infra,

    Tuotetun hukkalämmön määrä (MWh) ja siitä uudelleenkäytetty osuus,

    Vedyn ja veden käyttö (jos relevanttia, WUE-mittari),

    Uusiutuvan energian osuus (% tai MWh),

    Hiilidioksidipäästöt (Scope 2, tonneina).

Vihreän datakeskuksen kannalta nämä eivät ole vain raportoitavia lukuja, vaan johdon työkaluja. Niiden avulla tehdään päätöksiä investoinneista (kannattaako lisätä lämpöpumppu hukkalämmölle, jotta REF nousee?), operointistrategioista (ajetaanko joitain ei-kriittisiä kuormia yöaikaan, jolloin sähkö on vihreämpää?) ja yhteistyöstä (kumppanuus energian tuottajien kanssa). Kaikki palaa siihen, että dataa on hyödynnettävä – mittareiden on tarkoitus ohjata toimintaa, ei vain täyttää viranomaisvelvoitteita.

(Viitteet: EU:n energiatehokkuusdirektiivin 2023/1791 artikla 12 ja liite VII täsmentävät datakeskusten raportointivaatimuksia【20】. GHG Protocolin ohje [21] antaa periaatteet Scope 2 -raportointiin. ISO-standardeista [26][27] löytyy CUE ja REF tarkasti määriteltyinä.)
P7 – Datakeskusten energiatehokkuuden mittaaminen

Energiatehokkuuden mittaaminen on olennainen osa vihreän datakeskuksen hallintaa. Alan yhteiset mittarit mahdollistavat vertailun (benchmarking) ja parhaiden käytäntöjen tunnistamisen. Tässä luvussa esitellään keskeisimmät mittarit ja standardit, joita käytetään datakeskusten energiankäytön ja ympäristötehokkuuden arviointiin.

    Power Usage Effectiveness (PUE): kokonaisenergiankulutus / IT-energiankulutus. PUE on tunnetuin mittari, joka kertoo paljonko extraenergiaa kuluu tukijärjestelmiin yhtä IT-energiayksikköä kohti. PUE = 1,0 tarkoittaisi, ettei mene yhtään ylimääräistä energiaa infraan (kaikki menee IT:hen) – käytännössä ihanne. Tyypilliset nykylukemat ovat 1,2–1,5 välillä. Standardi ISO/IEC 30134-2:2016 määrittelee PUE:n tarkan laskennan ja mittausluokat【23】. PUE:ta voidaan parantaa mm. jäähdytyksen optimoinnilla, häviöiden vähentämisellä ja käyttöasteen nostolla.

    Cooling Efficiency Ratio (CER): IT-energiankulutus / jäähdytyksen energiankulutus. CER on uudempi mittari (ISO/IEC 30134-7:2023) joka tarkentaa jäähdytyksen tehokkuutta【24】. Se on tavallaan PUE:n osa-alue: jos CER = 5, se tarkoittaa että jokaista 5 kWh IT-energiaa kohden kuluu 1 kWh jäähdytykseen (eli jäähdytys on 20 %). Korkeampi CER on parempi (enemmän IT-työtä per jäähdytysenergia).

    Energy Reuse Factor (ERF): uudelleenkäytetyn energian osuus (%). ERF kertoo, kuinka suuren osan datakeskuksen kuluttamasta energiasta hyödynnetään sen ulkopuolella hyötykäyttöön (esim. hukkalämpönä). ISO/IEC 30134-6:2021 standardoi ERF:n【25】. Esim. ERF = 0,3 (30 %) tarkoittaa, että 30 % energiasta myydään vaikkapa kaukolämpöön. ERF parantaa tavallaan datakeskuksen kokonaistehokkuutta yhteiskunnan tasolla. Huom: The Green Grid esitteli myös ERE-mittarin (Energy Reuse Effectiveness), joka huomioi uudelleenkäytetyn energian PUE:n laskennassa【8】, mutta nykyisin suositellaan raportoitavan erikseen PUE ja ERF, jotta luvut ovat selkeitä.

    Renewable Energy Factor (REF): uusiutuvan energian osuus (%). ISO/IEC 30134-3:2016 määrittelee REF:n【27】. REF = 1,0 tarkoittaa että kaikki sähkö on peräisin uusiutuvista lähteistä (tai vastaavasti kompensoitu täysin). REF on tärkeä mittari hiilineutraaliustavoitteiden seurannassa.

    Carbon Usage Effectiveness (CUE): hiilidioksidipäästöt / IT-energia. CUE mittaa hiili-intensiteettiä (kgCO₂ per kWh). ISO/IEC 30134-8:2022 antaa standardin【26】. Jos datakeskus käyttää vain päästötöntä sähköä, CUE lähestyy nollaa. Jos käytössä on fossiilista sähköä, CUE on korkeampi. Esim. jos PUE = 1,3 ja sähköverkon päästökerroin 200 kg/MWh, CUE olisi noin 0,26 (eli 0,26 kgCO₂ per kWh IT:lle kulutettua sähköä).

    Water Usage Effectiveness (WUE): kulutetun veden määrä / IT-energiankulutus. Tämä mittari (The Green Grid määritellyt) kertoo, paljonko vettä datakeskus käyttää (jäähdytykseen tai muuhun) suhteessa sen IT-työhön. WUE on tärkeä erityisesti alueilla, joilla vedenkäyttö on kriittistä. Suomessa monet datakeskukset käyttävät ensisijaisesti ilmajäähdytystä, joten vedenkulutus on vähäistä, mutta jos käytetään esim. avojäähdytystorneja, WUE tulee mukaan kuvaan.

Kaikkien näiden mittareiden tarkoitus on ohjata toimintaa:

    PUE auttaa paikallistamaan, onko infra liikaa kuluttava suhteessa IT:hen.

    CER erottelee jäähdytyksen – jos CER on huono, keskitytään jäähdytyksen parantamiseen.

    ERF kannustaa hyödyntämään hukkalämpöä.

    REF ja CUE innostavat hankkimaan puhdasta energiaa ja vähentämään päästöjä.

    WUE motivoi vähentämään veden käyttöä (esim. käyttämään suljettuja vesikiertoja tai kuivan jäähdytyksen menetelmiä).

Säädösnäkökulma: EU:n uudistetussa energiatehokkuusdirektiivissä (2023) vaaditaan, että suuret datakeskukset raportoivat ainakin PUE:n ja tietyt muut luvut vuosittain kansalliselle viranomaiselle【20】. Suomessa Energiavirasto on ilmoittanut, että tämä raportointi alkaa vuodesta 2024 alkaen ja koskee yli 500 kW IT-tehon datakeskuksia【15】. Raportointitiedot – kuten PUE, uusiutuvan osuus, hukkalämmön määrä – kootaan EU-tason tietokantaan tulevaisuudessa. Tämä tarkoittaa, että mittaamisen on oltava kunnossa: datakeskusten on teknisesti kyettävä tuottamaan nämä luvut luotettavasti.

Yhteenveto: Energiatehokkuusmittarit tarjoavat konkreettiset tunnusluvut vihreälle datakeskukselle. Niiden säännöllinen seuranta ja raportointi varmistavat, että datakeskus pysyy tavoitteissaan ja että siitä voidaan viestiä sekä sisäisesti että ulkoisesti (asiakkaille, viranomaisille, yleisölle). Korkean hyötysuhteen omaavat laitokset, jotka raportoivat matalia PUE/CUE-arvoja ja korkeita uusiutuvan osuuksia, voivat myös käyttää tätä kilpailuetuna – monille asiakkaille konesalin ympäristöystävällisyys on nykyään tärkeä valintakriteeri.

(Luvun 7 lopuksi lukija on saanut kattavan kuvan siitä, millä mittareilla omaa datakeskusta kannattaa mitata ja millaisia arvoja tavoitella. Seuraavaksi mahdollisesti mentäisiin syventäviin menetelmiin (optimointiopas), mutta se on erillisen jatko-opuksen aihe.)
Lähteet

    Uddin, M. & Rahman, A. A. (2012). Energy efficiency and low carbon enabler green IT framework for data centers considering green metrics. Renewable and Sustainable Energy Reviews, 16(6), 4078–4094.

    Geng, H. (toim.). (2015). Data Center Handbook. John Wiley & Sons.

    Jin, X., Zhang, F., Vasilakos, A. V. & Liu, Z. (2016). Green Data Centers: A Survey, Perspectives, and Future Directions. arXiv (arXiv:1608.00687).

    Whitney, J. & Delforge, P. (2014). Data Center Efficiency Assessment – Scaling Up Energy Efficiency Across the Data Center Industry (NRDC Issue Paper IP:14-08-A).

    Wang, J., Palanisamy, B. & Xu, J. (2020). Sustainability-aware resource provisioning in data centers. IEEE CIC 2020, 60–67. DOI: 10.1109/CIC50333.2020.00018

    Barroso, L. A. & Hölzle, U. (2007). The Case for Energy-Proportional Computing. Computer, 40(12), 33–37.

    Liikenne- ja viestintäministeriö (LVM). (2020). ICT-alan ilmasto- ja ympäristövaikutukset – Väliraportti (Julkaisuja 2020:14).

    Elavarasi, J. et al. (2025). Green data centers: Advancing sustainability in the digital era. ICTMIM-2025 konferenssijulkaisu, 1817–1823.

    Andrae, A. S. G. & Edler, T. (2015). On global electricity usage of communication technology: Trends to 2030. Challenges, 6(1), 117–157.

    Sharma, P., et al. (2017). Design and operational analysis of a green data center. IEEE Internet Computing, 21(4), 16–24.

    Barroso, L. A., Hölzle, U. & Ranganathan, P. (2022). The Datacenter as a Computer: Designing Warehouse-Scale Machines (3rd ed.). Springer.

    Bilal, K. et al. (2014). A Taxonomy and Survey on Green Data Center Networks. Future Generation Computer Systems, 36, 189–208.

    Oró, E., et al. (2015). Energy efficiency and renewable energy integration in data centres: Strategies and modelling review. Renewable and Sustainable Energy Reviews, 42, 429–445.

    National Institute of Standards and Technology (NIST). (2014). Guidelines for Media Sanitization (Special Publication 800-88 Rev. 1).

    Baldé, C. P., et al. (2017). The Global E-waste Monitor 2017: Quantities, Flows, and Resources. YK/ITU/ISWA.

    Li, J., et al. (2015). Control-Alt-Delete: Rebooting solutions for the e-waste problem. Environmental Science & Technology, 49(12), 7095–7102.

    Whitehead, B., et al. (2015). The life cycle assessment of a UK data centre. Int. Journal of Life Cycle Assessment, 20, 332–349.

    Schneider Electric – Data Center Science Center. (2015). Fundamentals of Managing the Data Center Life Cycle for Owners (White Paper).

    UNEP DTU Partnership. (2020). Environmental sustainability of data centres: A need for a multi-impact and life-cycle approach.

    Lawrence Berkeley National Laboratory (LBNL). (2023). Best Practices Guide for Energy-Efficient Data Center Design (Draft 2025).

    GHG Protocol. Scope 2 Guidance – An amendment to the GHG Protocol Corporate Standard.

    ASHRAE. Thermal Guidelines for Data Processing Environments (viitattu Dallas Chapter -esitykseen, 2016).

    ISO/IEC 30134-2:2016 – Information technology — Data centres — Key metrics — Part 2: Power usage effectiveness (PUE).

    ISO/IEC 30134-7:2023 – Information technology — Data centres — Key metrics — Part 7: Cooling efficiency ratio (CER).

    ISO/IEC 30134-6:2021 – Information technology — Data centres — Key metrics — Part 6: Energy Reuse Factor (ERF).

    ISO/IEC 30134-8:2022 – Information technology — Data centres — Key metrics — Part 8: Carbon usage effectiveness (CUE).

    ISO/IEC 30134-3:2016 – Information technology — Data centres — Key metrics — Part 3: Renewable Energy Factor (REF).

    Fortum. (2021). Datacentres Helsinki region – Fortumin & Microsoftin datakeskushankkeen esittely (verkkosivu).

    Google. (2022). Our first offsite heat recovery project lands in Finland – Google Europen blogi 2.11.2022 (Hamina-hankkeen uutinen).

Citations
GitHub

perusopas_new.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_new.md#L74-L82
GitHub

perusopas_new.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_new.md#L5-L13
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L9-L11
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L2-L10
GitHub

perusopas_new.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_new.md#L58-L61
GitHub

perusopas_new.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_new.md#L67-L75
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L93-L101
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L70-L78
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L78-L84
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L95-L101
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L99-L103
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L99-L101
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L99-L102
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L101-L104
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L110-L118
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L126-L134
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L128-L136
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L132-L136
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L2-L5
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L375-L383
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L380-L388
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L372-L379
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L42-L48
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L42-L50
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L416-L424
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L417-L425
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L419-L421
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L423-L431
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L427-L431
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L429-L431
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L680-L688
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L681-L689
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L679-L687
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L740-L748
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L748-L755
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L750-L758
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L752-L760
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L762-L770
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L760-L769
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L768-L776
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L770-L776
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L772-L776
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L780-L788
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L782-L790
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L786-L794
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L792-L797
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L854-L863
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L860-L868
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L862-L870
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L868-L876
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L870-L878
GitHub

perusopas_FIN.md
https://github.com/kopja3/green_DC/blob/91a0ca62acd837743ad258f06f8eb194e3f5fbfa/docs/perusopas/perusopas_FIN.md#L872-L876
All Sources
github
