# Energian kulutus datakeskuksessa:

Datakeskuksen sähköenergiankulutuksen neljä pääkategoriaa:

- **Eₛ (servers)** – palvelinten energiankulutus  
- **Eₛₜ (storage)** – tallennuslaitteiden energiankulutus  
- **Eₚ (network)** – verkkolaitteiden energiankulutus  
- **Eᵢ (infrastructure)** – tukijärjestelmien, kuten jäähdytyksen, UPS-järjestelmien ja valaistuksen, energiankulutus  

Yhteensä nämä muodostavat datakeskuksen kokonaiskulutuksen:

**E = Eₛ + Eₛₜ + Eₚ + Eᵢ**

Jaottelu auttaa hahmottamaan, että datakeskuksen sähköenergian kulutus jakautuu palvelimiin, tallennuslaitteisiin, verkkolaitteisiin ja tukijärjestelmiin (kuten jäähdytys ja varavirtaratkaisut). Tukijärjestelmien osuus voi kasvaa merkittäväksi, erityisesti silloin kun niiden toiminnan energiatehokkuuteen ei ole kiinnitetty huomiota [1].

Palvelimissa suorittimet (CPU, GPU), levyt (I/O) ja verkkolaitteet (NIC) suorittavat datakeskuksen varsinaiset laskenta- ja tietoliikennetehtävät.

Suurin yksittäinen energiankuluttaja on palvelimissa suoritin, jonka kulutus kasvaa laskentakuorman, ytimien määrän ja kellotaajuuden myötä ~50-60%. Levylaitteistot kuluttavat merkittävästi energiaa erityisesti kirjoitusoperaatioissa ~20-30%, ja verkkolaitteiden kulutus riippuu voimakkaasti siirtonopeudesta ja pakettikoon hallinnasta ~10-20%, lisäksi palvelimella on muuta esimerkiksi käyttöjärjestelmän aiheuttamaa taustakulutusta ~10-20. [2]
~


## Energiatehokkuuden mittaaminen (PUE):
Keskeinen energiatehokkuuden mittari on PUE (Power Usage Effectiveness)
PUE-arvo saadaan vertaamalla datakeskuksen
kokonaisenergiankulutusta IT-laitteiden kulutukseen. Ideaalisesti PUE olisi 1,0 (kaikki energia
menee laskentaan), mutta käytännössä aina on jonkin verran ylimääräistä kulutusta. Esimerkiksi,
jos PUE on vaikkapa 2, se tarkoittaa että jokaista palvelinten käyttämää kilowattituntia kohden
toinen kilowattitunti kuluu tukitoimintoihin. Modernit hyvin suunnitellut datakeskukset voivat
saavuttaa PUE-lukuja lähellä 1,1–1,2.

## Datakeskuksen energiankulutuksen vähentäminen:
Virtualisoinnin avulla sama laitemäärä palvelee useampia käyttäjiä (parannetaan käyttöastetta, ettei palvelimet seiso tyhjän panttina),
Lämpötilaolosuhteiden optimointi (kaikkien tilojen ei tarvitse olla jääkaappikylmiä – nykylaitteet
kestävät hieman korkeampia lämpötiloja turvallisesti, mikä voi vähentää jäähdytystarvetta), 
Jäähdytyksen energiatehokkuusratkaisut (vapaajäähdytys ulkoilmalla kylminä vuodenaikoina tai
lämpimän ja kylmän ilmankierron erottelu palvelinsaleissa, jotta jäähdytys kohdistuu tehokkaasti oikeisiin paikkoihin).

## Hukkalämmön talteenotto:
Kun palvelimet käyvät, ne muuttavat sähköenergian lämmöksi. 
Normaalisti tämä lämpö johdetaan pois (esim. puhalletaan ulkoilmaan tai jäähdytysveden mukana mereen), 
mutta vihreässä ajattelussa lämpö on arvokas sivutuote.
Lämmön talteenottojärjestelmät (kuten lämpöpumput ja lämmönvaihtimet) voivat siirtää palvelinsalin hukkalämmön esimerkiksi
kaukolämpöverkkoon tai lähirakennusten lämmitykseen. 
Tällöin sama energia hyödynnetään kahdesti: ensin digipalveluiden pyörittämiseen ja sitten rakennusten lämmittämiseen.

Hukkalämmön hyödyntäminen parantaa kokonaishyötysuhdetta ja vähentää yhteiskunnan primäärienergian tarvetta. 
Jokainen kilowattitunti, joka saadaan talteen datakeskuksesta ja käytetään vaikkapa talojen lämmitykseen, on kilowattitunti vähemmän
polttoaineita kattiloissa tai sähköä erillisissä lämpölaitoksissa. 
Samalla datakeskuksen toimintaa voidaan perustella ympäristöystävällisempänä (vähemmän hukkaa).

Hukkalämmön hyödyntäminen ei ole aivan triviaalia: se vaatii investointeja (esim. lämpöpumppuihin, putkistoihin) ja edellyttää, että lähettyvillä on
lämmön tarvetta (esimerkiksi kaupunki tai teollisuuslaitos, joka voi hyödyntää lämpöä). 
Aina tämä ei toteudu – tästä syystä kaikki datakeskukset eivät vielä kierrätä lämpöään.

kaavio, jossa on kaksi rinnakkaista kuvaa: perinteinen datakeskus vs. hukkalämpöä hyödyntävä datakeskus. 
Ensimmäisessä sähkö syötetään datakeskukseen ja lopputuloksena lämpö menee harakoille (piirrä nuoli lämpönä ulos ympäristöön). 
Toisessa kuvassa sähkö (mieluiten uusiutuva) menee datakeskukseen ja syntyvä lämpö ohjataan lämpöpumppujen kautta kaukolämpöverkkoon tai kasvihuoneille tms. 
Kuvaan voi merkitä, kuinka sama energia palvelee kahta tarkoitusta. (Tämän kuvan avulla opiskelija hahmottaa konkreettisesti, miten datakeskuksen tuottama lämpö voidaan muuttaa ongelmasta resurssiksi.)

Esimerkki: Telia Helsinki Data Center Pitäjänmäellä. 
Telian suuri datakeskus Helsingissä on kytketty energiayhtiö Helenin kaukolämpöverkkoon.
Käytännössä tuhansien palvelimien tuottama lämpö kerätään talteen ja ohjataan lämpöpumppujen avulla lämmittämään helsinkiläisiä koteja ja käyttövetä.
Telian datakeskuksen hukkalämmöllä voidaan kattaa tuhansien kotitalouksien lämmöntarve. 
Tämä esimerkki osoittaa, kuinka datakeskuksen jäte-energia muuttuu hyödylliseksi palveluksi kaupunkilaisille.
Yandexin datakeskus Mäntsälässä oli Suomen ensimmäisiä,joka ryhtyi lämmittämään koko lähikuntaa palvelinsalien hukkalämmöllä, ja Kajaanin uusi
LUMI-supertietokone syöttää hukkalämpönsä kaupungin kaukolämpöverkkoon. 
Energian kierrätys datakeskuksista on jo todellisuutta Suomessa.
Jatkolukuvinkki: Ylen uutinen “Datakeskusten hukkalämpöä on pian pakko hyötykäyttää” (7.6.2023) käsittelee, kuinka EU ja kaupungit kannustavat datakeskuksia hyödyntämään lämpöään entistä tehokkaammin.

Pohdintatehtävä (vapaaehtoinen): 
Miksi luulet, ettei kaikissa datakeskuksissa vielä kierrätetä hukkalämpöä? 
Pohdi, millaisia esteitä tai haasteita hukkalämmön hyödyntämiseen voi liittyä (taloudelliset kustannukset, sijainti, tekniset rajoitteet jne.).

[1] Arman Shehabi et al. 2018 Environ. Res.Lett. 13 124030.
[2] Arjona et al., "A Measurement-based Analysis of the Energy Consumption of Datacenter Services", arXiv:1402.0804v1 (2014).






