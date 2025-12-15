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

P1.5 Vihreän datakeskuksen pääelementit yhdellä kuvalla

Alla oleva kuva kokoaa vihreän datakeskuksen keskeiset osa-alueet yhteen kokonaisuuteen. Se näyttää neljä päähaaraa, joihin oppaan myöhemmät luvut palaavat tarkemmin:
ICT-laitteiden energiatehokkuus – miten palvelimet, tallennus ja verkkolaitteet suunnitellaan ja säädetään niin, että ne kuluttavat mahdollisimman vähän sähköä (dynaaminen suoritusnopeuden säätö, virrankatkaisumekanismit, hybridiratkaisut).
Resurssienhallinta – miten laskenta, verkko ja sähkö jaetaan tehokkaasti (virtuaalikoneiden resurssien jako, verkkoliikenteen optimointi, sähkönjakelu ja uusiutuvan energian hyödyntäminen).
Lämpötilanhallinta – miten jäähdytys, työkuormien jako ja lämpötilatasot pidetään sellaisina, että energiatehokkuus ja järjestelmän luotettavuus ovat tasapainossa.
Vihreät suorituskykymittarit – miten datakeskuksen toimintaa mitataan ja seurataan (esimerkiksi PUE-, CUE- ja WUE-tyyppiset mittarit sekä vihreä monitorointi ja kokeelliset tekniikat).

<p> <img src="./img/p1-kuvaX-vihrean-datakeskuksen-osa-alueet.png" alt="Kuva X. Vihreän datakeskuksen keskeiset osa-alueet: ICT-laitteiden energiatehokkuus, resurssienhallinta, lämpötilanhallinta ja vihreät suorituskykymittarit." style="width:100%;height:auto;"> </p>

Kuva X. Vihreän datakeskuksen keskeiset osa-alueet. Kuva toimii karttana oppaan myöhempiin lukuihin, joissa kutakin haaraa käsitellään tarkemmin.
