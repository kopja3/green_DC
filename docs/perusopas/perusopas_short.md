# P1 Johdanto vihreään datakeskukseen

Tavoite: määrittää oppaan rajaus ja käsitteet sekä yhtenäinen mitoitus- ja mittauskieli (energia E, teho P, kapasiteetti C, palvelutaso SLA/SLO) päätös→tuotos→mittaus -ketjun pohjaksi.

## P1.1 Miksi perusopas?

Opas tukee vihreän datakeskuksen suunnittelua ja toteutusta Suomessa. Se jäsentää päätökset vaiheisiin ja liittää ne mitattaviin suureisiin: energia (E), teho (P), kapasiteetti (C) ja palvelutaso (SLA/SLO).  

Oppaan rakenne:

- **Luku 2:** Sijaintipäätökset – sähkö, verkko, viive, jäähdytys ja hukkalämpöliitynnät.  
- **Luku 3:** Vihreän datakeskuksen peruselementit – osa-alueet ja mittausrajat.  
- **Luku 4:** Elinkaari – suunnittelu, rakentaminen, käyttö ja käytöstäpoisto, data ja materiaalivirrat.  
- **Luku 5:** Toiminta – kuorma ja palvelutaso → kapasiteetti → IT-tehon vaihtelu → sähkö- ja jäähdytysinfrastruktuurin mitoitus.  
- **Luku 6:** Energian kulutus ja uudelleenkäyttö – kulutuserät, jäähdytys, hukkalämpö, rajapinnat.  
- **Luku 7:** Energiatehokkuuden mittaaminen – PUE, REF, ERF, CER, CUE, WUE, mittauspisteet.

## P1.2 Mikä on vihreä datakeskus?

Vihreä datakeskus yhdistää suunnittelun ja operoinnin energian ja päästöjen mittaamiseen ja raportointiin. Keskeiset osa-alueet:

- **Kuorma ja kapasiteetti:** työkuorman kuvaus, kapasiteetin mitoitus ja IT-tehon vaihtelu.  
- **Sähkönsyöttö ja varmistus:** sähköliittymä, jakelu, UPS/varavoima ja häviöt.  
- **Sähkön alkuperä ja päästöt:** hankintatapa, todentaminen ja päästökertoimet.  
- **Jäähdytys:** jäähdytysarkkitehtuuri ja sen sähköteho suhteessa IT-tehoon.  
- **Hukkalämpö:** talteenotto, mittaus ja luovutusrajapinta.  
- **Elinkaaren loppu:** käytöstäpoisto, tietojen hävittäminen, materiaalivirrat.

Osa-alueiden päätökset ja toteutus käsitellään luvussa 3 ja päätös→tuotos→luku -rakenteessa luvussa P1.8.

## P1.3 Miten opasta käytetään?

Opasta käytetään päätöksenteon ja dokumentoinnin tukena:

1. **Määritä lähtötiedot ja rajaukset:** työkuorma, palvelutaso, mittausrajat (kokonaisenergia ja IT-energia).  
2. **Johda mitoitusketju:** työkuorma → kapasiteetti → IT-teho ajassa → sähköliittymä, jakelu, varmistus ja jäähdytys.  
3. **Valitse mittarit ja todennus:** määritä mittauspisteet, todentamistavat ja päästökertoimet.  
4. **Käytä menettelyä toteutuksessa:** mittaa → analysoi → muutos → todenna → vakioi.

# P1.4–P1.9 Datakeskuksen tehomitoitus, kapasiteetti ja vihreän datakeskuksen periaatteet

## P1.4 Tehomitoitusketju

**Keskeiset suureet ja termit:**

- **Teho (P):** hetkellinen sähköteho [W, kW, MW].  
- **Energia (E):** teho aikajaksolla [Wh, kWh, MWh].  
- **IT-työkuorma L(t):** saapuvien työ- ja palvelupyyntöjen määrä ja ominaisuudet ajan funktiona.  
- **SLA/SLO:** palvelutasosopimus ja mitattava tavoitetaso (esim. saatavuus, vasteaika).  
- **Kapsiteetti:**  
  - C_inst: asennettu kokonaiskapasiteetti  
  - C_act(t): aktiivinen kapasiteetti  
  - C_res: varakapasiteetti huippujen ja vikojen varalle  
- **IT-teho P_IT(t):** aktiivisen kapasiteetin sähköteho.  
- **Lämpökuorma Q_th(t):** jäähdytyksen poistettava lämpöteho.  
- **Jäähdytyksen sähköteho P_cool(t):** jäähdytysjärjestelmien ottama teho.  

**Tehomitoitusketju:**  
L(t) + SLA/SLO (+ saatavuus) → C_act(t) + C_res → P_IT(t) → sähkö- ja jäähdytysinfrastruktuuri.  
Varmistusperiaatteet (N+1, 2N) lisäävät kapasiteettivaraa. Vihreässä datakeskuksessa huomioidaan lisäksi energian alkuperä, mittausrajat ja hukkalämmön hyötykäyttö.

## P1.5 IT-työkuorman ja kapasiteetin mallinnus

- Työpyyntöjen ryhmittely ja työtyyppien profiilit (workload characterization).  
- Kuorman ennuste tuleville aikajaksoille (workload prediction).  
- Kapasiteettisuunnittelu: päätös aktiivisesta ja varakapasiteetista C_act(t), C_res; sijoitus palvelimille (job–server mapping).  
- Mitoitus voidaan mallintaa ILP-ongelmana, käytännössä heuristiikat riittävät [7].  
- Vaihtoehtoinen lähtötieto: sovellus- ja alustatason ennusteet, järjestelmäuudistusten huomioiminen.  
- Sähkötehon mitoituksessa huomioidaan pätöteho, loisteho, näennäisteho ja tehokerroin.

**Yhteenveto:** IT-teho P_IT,max johdetaan ennusteista tai sovellusarkkitehtuurista, ja tämän perusteella mitoitetaan sähkö- ja jäähdytysinfrastruktuuri.

## P1.6 Käyttöaste ja kuormariippuvuus

- Käyttöaste vaikuttaa sähkönkulutukseen: IT-laitteiden teho koostuu kuormaan sidotusta osasta ja perustehosta.  
- Perinteisissä yritysdatasaleissa käyttöaste on matala, hyperskaalassa korkeampi.  
- Kuorman vaihtelu, ennusteen epävarmuus ja SLA/SLO vaatimukset lisäävät varakapasiteetin tarvetta.  
- Palvelinten sähkönkulutus ei ole täysin energiaproportionaalista; kapasiteetin mitoitus ja kuormanohjaus vaikuttavat energiankulutukseen ja päästöihin.

## P1.7 Kansainvälinen kehitys ja Suomen reunaehdot

- Datakeskusten määrä kasvaa digitalisaation ja pilvipalveluiden myötä; vanhat hajautetut ympäristöt korvataan keskistetyillä ratkaisuilla.  
- Maailmanlaajuinen sähkönkulutus ~1 % datakeskuksista, kasvutrendi suuri ilman energiatehokkuustoimia.  
- Suomessa sähköverkko on pääosin uusiutuvaa; ulkoilmaolosuhteet mahdollistavat usein free coolingin.  
- Päästöjen arviointi: sähköenergia × päästökertoimet; laajemmin huomioidaan varavoima, jäähdytys ja elinkaaren päästöt.

## P1.8 Vihreän datakeskuksen elementit ja päätöspisteet

- Päätökset esitetään muodossa **päätös → tuotos → luku**.  
- Keskeiset päätökset:  
  - **Sijainti:** sähkö, verkko, liityntä, viive, saatavuus → Luku 2  
  - **Työkuorma ja SLA/SLO:** L(t), palvelutasorajat → Luku 5  
  - **Kapasiteetti:** C_inst, C_act(t), C_res → Luku 5  
  - **IT-tehoprofiili:** P_IT(t) → Luku 5  
  - **Sähköketju ja varmistus:** UPS/varavoima, häviöt → Luku 5  
  - **Sähkön alkuperä ja päästöt:** hankinta, todentaminen → Luku 6  
  - **Jäähdytysratkaisu:** P_cool(t), lämpökuorma → Luku 6  
  - **Hukkalämpö:** mittaus ja hyötykäyttö → Luku 6  
  - **Mittarit ja raportointi:** PUE, REF, ERF, CER, CUE, WUE → Luku 7  
  - **Elinkaaren loppu:** käytöstäpoisto, materiaalivirrat → Luku 4  

## P1.9 Miksi sijainti käsitellään ensin

- Sijainti määrittää sähköverkon kapasiteetin, palvelutasovaatimukset, päästöt, free cooling-mahdollisuudet ja hukkalämmön hyötykäytön.  
- Kuorman siirto alueiden välillä riippuu viiveestä ja palvelutasosta; Suomessa viiveet ovat yleensä pienempi haaste.

# P2 – Miksi datakeskus rakennetaan ja miten sijainti valitaan

**Tavoite:**  
Luoda läpinäkyvä ja toistettavissa oleva prosessi datakeskuksen ajureiden, toteutusmallin ja sijainnin valinnalle ennen suunnittelua ja mitoitusta.

## 1. Rakentamisen ajurit
- **Teknologiset:** Viive- ja suorituskykyvaatimukset, korkea tehotiheys, paikallinen käsittely (esim. edge, HPC/AI).  
- **Liiketoiminnalliset:** Pilvipalvelujen ja digitalisaation kasvun tukeminen, energiatehokkuus, operoinnin tehostaminen.  
- **Yhteiskunnalliset:** Kriittiset palvelut, toimintavarmuus, ympäristövaikutukset, kansalliset reunaehdot.  

*Pääajuri ohjaa painotuksia ja kompromisseja toteutus- ja sijaintiratkaisuissa.*

### Toimijakartta
| Toimija | Päätavoite | Pääluokka |
|---------|------------|-----------|
| Hyperscale / pilvitoimija | Lisätä kapasiteettia nopeasti | Liiketoiminnallinen |
| Colocation / konesalipalvelu | Tarjota luotettavaa kapasiteettia asiakkaille | Liiketoiminnallinen |
| Enterprise / oma konesali | Hallittu ja turvallinen liiketoiminta | Liiketoiminnallinen |
| Edge | Laskenta lähellä käyttäjää, matala viive | Teknologinen |
| HPC/AI-klusterit | Maksimoida suorituskyky erikoiskuormille | Teknologinen |
| Julkinen / kriittinen infra | Varmistaa kriittisten palvelujen jatkuvuus | Yhteiskunnallinen |

## 2. Toteutusmallit
- **Oma datakeskus:** Pitkäaikainen kapasiteettitarve, korkeat tietoturva- ja räätälöintivaatimukset.  
- **Colocation:** Pienemmät rakennus- ja infrastruktuuri-investoinnit, oma laitteisto ja hallinta.  
- **Pilvi:** Skaalautuvuus, joustava kapasiteetti, palvelut “on-demand”, rajallinen fyysinen kontrolli.  
- **Hybridi:** Kriittiset palvelut omassa/kumppanin keskuksessa, muu kuorma pilvessä.

## 3. Sijainnin tekniset tekijät
- **Sähkö:** Kantaverkko, kapasiteetti, varasyötöt, redundanssi.  
- **Tietoliikenne:** Nopeat ja luotettavat yhteydet, multiple ISP:t, redundanssi.  
- **Ilmasto:** Free cooling -mahdollisuus, jäähdytyksen energiankulutus.  
- **Vesihuolto:** Veden saatavuus ja kestävyys, jäähdytysratkaisut.

## 4. Ympäristö- ja energiatehokkuus
- **Uusiutuva energia:** Saatavuus, sertifiointi, PPA/GoO.  
- **Hukkalämmön hyödyntäminen:** Kaukolämpöverkko, teollisuus, asuminen.  
- **Jäähdytys:** Ilmasto riippuva, free cooling -tuntipotentiaali.  
- **Vesivarojen kestävyys:** Minimoi makean veden käyttö, kierrätys.

## 5. Riskit, resilienssi ja regulaatio
- **Sähkökatkot ja verkkohäiriöt**  
- **Sää- ja ilmastoriskit** (myrskyt, lumikuormat, helleaallot)  
- **Paikalliset turvallisuusriskit** (rikollisuus, ilkivalta)  
- **Yhteyskatkokset** (kaapeliviat, operaattorit)  
- **Kyberuhat ja geopoliittiset tekijät**  

*Varmistukset:* redundanssi, varayhteydet, varakonesali.  
*Lupavaatimukset:* kaavoitus, ympäristölupa, datan sijainti, melu- ja päästörajat.

## 6. Tavoitetason ja mittarit
- **PUE (Power Usage Effectiveness)** – kokonaisenergia / IT-energia  
- **CUE (Carbon Usage Effectiveness)** – hiilidioksidipäästöt / IT-energia  
- **WUE (Water Usage Effectiveness)** – vedenkulutus / IT-energia  
- **ERF (Energy Reuse Factor)** – uudelleenkäytetty energia  
- **REF (Renewable Energy Factor)** – uusiutuvan energian osuus  

## 7. Sijaintivalinnan menettely
1. **Porttikriteerit (go/no-go)**  
   - Sähköverkko ja kapasiteetti, redundanssi  
   - Sähkön päästöintensiteetti ja uusiutuva energia  
   - Ilmasto ja free cooling  
   - Hukkalämmön vastaanotto  
   - Riskit ja lupavaatimukset  
   - Latenssi- ja käyttäjävaatimukset

2. **Pisteytys ja painotus (1–5)**  
   - Esim. sähkö 35 %, lämpöintegraatio 20 %, jäähdytysilmasto 15 %, kuitu 15 %, vesi + lupitus 15 %  
   - Perustelut jokaiselle pisteelle, herkkyystarkistus painojen muutoksella  
   - Valitaan 1–2 jatkoselvityskohdetta + varavaihtoehto  

## 8. Tuotokset
- Go/no-go -muistio sijaintivaihtoehdoista  
- Pisteytystaulukko, painotukset ja herkkyystarkastelu  
- Sähkö- ja energiadokumentaatio, uusiutuvan energian todentaminen  
- Jäähdytyksen ja hukkalämmön alustava toteutettavuuskuvaus  
- Viive- ja saavutettavuusreunaehdot  

**Lopputulos:** Selkeä käsitys datakeskuksen ajureista, toteutusmallista, sijaintikriteereistä ja tavoite-/mittaritasoista, joka muodostaa perustan seuraaville suunnitteluvaiheille.
# 3 – Vihreän datakeskuksen peruselementit ja periaatteet

**Tavoite:** Kuvata vihreän datakeskuksen keskeiset elementit, niiden suunnitteluperiaatteet ja kestävän kehityksen toteutus elinkaaren eri vaiheissa.

## 3.1 Mitä tarkoitetaan vihreällä datakeskuksella
- Minimoi energiankulutus ja ympäristöhaitat koko elinkaaren ajan.  
- Toteutuu tasoilla:
  - Energiatehokkuus: tehokkaat palvelimet, virtalähteet, vapaajäähdytys.  
  - Uusiutuva energia: paikallinen tuotanto tai sertifioitu ostosähkö, vähäpäästöiset varavoimalähteet.  
  - Hukkalämmön hyödyntäminen: lämmön talteenotto kaukolämpöön tai paikallisiin kohteisiin.  
  - Automaatio ja optimointi: AI- ja BMS/DCIM-järjestelmät, reaaliaikainen kuormien ja jäähdytyksen ohjaus.  
  - Kestävä rakentaminen ja materiaalit: pitkäikäiset, modulaariset ja kierrätettävät rakenteet ja laitteet.

## 3.2 Rakennus- ja tilaratkaisut
- **Yksikerroksinen:** helppo huolto, jäähdytys ja ilmavirtojen hallinta.  
- **Monikerroksinen:** säästää tonttia, vaatii tarkkaa sähkö- ja ilmankiertosuunnittelua.  
- **Konttidatakeskus:** modulaarinen, helposti laajennettavissa, hyvä tehotiheys ja jäähdytyksen hyötysuhde.  
- **DBO-malli:** sama toimija vastaa suunnittelusta, rakentamisesta ja operoinnista → energiatehokkuustavoitteet toteutuvat paremmin.  
- **Suunnitteluohje:** mitoita todellisen tarpeen mukaan, varmista modulaarisuus, ilmatiiveys ja tehokas ilman-/lämpövyöhykkeiden hallinta.

## 3.3 Sähkö- ja energiajärjestelmän periaatteet
- Luotettava, mutta ei ylivarmentava sähköjärjestelmä.  
- Ketju: kantaverkko → muuntajat → UPS → PDU → palvelinkaapit.  
- Modernit UPS- ja muuntajateknologiat minimoivat häviöt ja tyhjäkäynnin energiankulutuksen.  
- Varavoima: fossiilivapaa tai uusiutuvaa polttoainetta käyttävät generaattorit, säännöllinen testaus optimikäytöllä.  
- Tavoite: riittävä luotettavuus ilman turhia tehonsyöppöjä, PUE:n optimointi.

## 3.4 Jäähdytysratkaisut ja ilmankierto
- **Ilmajäähdytys:** kylmä-kuuma-käytävä -periaate, korkeampi palvelinsalilämpötila (esim. 27 °C) vähentää kompressorin tarvetta.  
- **Nestejäähdytys:** tehokas lämmönsiirto, monimutkaisempi järjestelmä.  
- **Adiabattinen jäähdytys:** haihdutus veden avulla, säästää sähköä.  
- **Free cooling:** ulkoilman hyödyntäminen suurimman osan vuodesta.  
- Optimointi: suljetut käytävät, peitelevyt, moduulijäähdytys, jatkuva automaatio.

## 3.5 Hukkalämmön talteenotto
- Lähes kaikki IT-energia muuttuu lämmöksi, joka voidaan hyödyntää.  
- Kaukolämpöön syöttäminen lämpöpumpuilla → energiatehokkuus + päästövähennys.  
- Vaihtoehtoja: paikalliset lämmönkulutuskohteet (kasvihuoneet, teollisuus, asuinrakennukset).  
- Hyöty: pienentää datakeskuksen ja alueen päästöjä, mahdollinen lisäarvo/markkinahinta.

## 3.6 Uusiutuvan energian integraatio
- Paikalliset lähteet tai ostosähkö PPA-sopimuksin.  
- Aurinkopaneelit: katot ja seinät, kesäkuormaan osuvasti.  
- Tuulivoima: omat turbiinit tai PPA-sopimukset.  
- Energiavarastot: akut, vety, peak shaving, kuorman optimointi.  
- Tavoite: lisätä uusiutuvan osuutta ja vähentää hiilijalanjälkeä (CUE) vaarantamatta jatkuvuutta.

## 3.7 Automaatio, mittaus ja optimointi
- Sensoreita ja BMS/DCIM-järjestelmiä jatkuvaan seurantaan.  
- Mitataan: sähkönkulutus, lämpötila, ilmankosteus, laitekohtainen kuorma.  
- Reaaliaikainen optimointi: kuormansiirrot, vajaatehoisten laitteiden lepotila, jäähdytyksen säätö.  
- AI hyödyntäminen trendien ja poikkeamien tunnistukseen (esim. Google DeepMind: ~40 % jäähdytyssäästö).  
- Automaatio tukee energiatehokkuutta ja palvelutason parantamista.

## 3.8 Kestävät materiaalivalinnat ja kiertotalous
- Modulaarisuus ja pitkän käyttöiän komponentit vähentävät ympäristökuormaa.  
- Kierrätettävyys: rakennusmateriaalit, palvelinlaitteet, UPS-osat.  
- Elinkaariajattelu: purku ja kierto suunniteltava alusta asti.  
- Kiertotalous näkyy operoinnissa: varaosien uudelleenkäyttö, vaarallisten aineiden asianmukainen kierrätys.  
- Kokonaisuus: elinkaaren hallinta, modulaarisuus, pitkäikäisyys ja kierrätettävyys minimoivat ympäristöjalanjäljen.

# 4. Datakeskuksen elinkaaren vaiheet

Tämä luku kuvaa datakeskuksen elinkaaren vaiheet esiselvityksestä käytöstäpoistoon, huomioiden vihreän ICT:n näkökulma (energia, päästöt, vesi, materiaalit, raportointi).

## 4.1 Esiselvitys ja tavoitteiden asettaminen
- Määritellään datakeskuksen rooli, kapasiteetti ja palvelutasot (SLA).  
- Asetetaan vihreät tavoitteet: PUE, CO₂-taso, uusiutuvan energian osuus, WUE, hukkalämmön hyödyntäminen.  
- Tuotokset: hankkeen peruskirja, päätös datakeskuksen toteutusmallista (oma, pilvi, hybridi).  

## 4.2 Suunnitteluvaihe
- Konkreettiset ratkaisut: rakennuksen koko, sähkö- ja jäähdytysjärjestelmät, automaatio ja valvonta.  
- Tilavaraukset tuleville teknologioille.  
- Vihreät tavoitteet sisällytetään suunnitteluun (PUE, uusiutuva energia, hukkalämmön hyödyntäminen).  
- Sertifiointien ja standardien huomiointi (LEED, BREEAM, ISO 14001, ISO 50001).  
- Porttipäätös: suunnitelman hyväksyntä ennen rakentamista.  

## 4.3 Rakentaminen
- Fyysisen datakeskuksen toteutus.  
- Ympäristöystävällinen työmaa: jätteiden lajittelu, päästöjen minimointi, kierrätys.  
- Rakenteet: vähähiilinen betoni, kierrätysteräs, tiiveys ja eristys energiatehokkuuden varmistamiseksi.  
- Sähkö- ja jäähdytysjärjestelmien, kaapeloinnin ja valvonnan asennus.  
- Dokumentointi ja laadunvarmistus.

## 4.4 Käyttöönotto
- Järjestelmien testaus: sähkö, jäähdytys, automaatio, kuormitus ja turvallisuus.  
- Ensimmäiset mittaukset: PUE, verkon suorituskyky, hukkalämmön hyödyntäminen.  
- Hyväksymistarkastus ja siirto operointitiimille.  

## 4.5 Käyttö, operointi ja ylläpito
- Palveluiden saatavuuden varmistaminen, vikatilanteiden hallinta.  
- Energiankulutuksen, hiilidioksidipäästöjen, vedenkulutuksen ja hukkalämmön seuranta.  
- Ennakoiva huolto, koneoppimisen hyödyntäminen ja resurssien optimointi.  
- Dokumentointi, varautumissuunnitelmat, vastuuhenkilöiden nimeäminen.  
- Jatkuva optimointi energiatehokkuuden ja ympäristötavoitteiden saavuttamiseksi.  

## 4.6 Modernisointi ja kapasiteetin laajennus
- Laitteistojen päivitys energiatehokkaammiksi (palvelimet, tallennus, jäähdytys).  
- Kapasiteetin lisäys modulaarisesti: uusia kaappeja, palvelimia, moduulitiloja.  
- Uusiutuvan energian osuuden kasvattaminen, hukkalämmön hyödyntäminen.  
- Modernisointi yhdistetään operointiin, dokumentointiin ja henkilöstön koulutukseen.

## 4.7 Purku ja elinkaaren loppu
- Rakennusmateriaalien, elektroniikan ja vaarallisten aineiden kierrätys ja uudelleenkäyttö.  
- Tontin hyödyntäminen uudelleen (akkuvarasto, sähköasema).  
- Modulaariset ja helposti purettavat rakenteet tukevat kiertotaloutta.  
- Tavoitteena lähes 0-jätettä.

## 4.8 Kestävä ja modulaarinen suunnittelu
- Modulaarisuus ja pitkäjänteisyys läpäisevät kaikki elinkaaren vaiheet.  
- Suunnittelu, rakentaminen, operointi, modernisointi ja purku tukevat modulaarisuutta.  
- Elinkaari hallitaan kokonaisuutena: palveluiden kehitys ja ympäristökuormitus optimoidaan.

## 4.9 Tulevaisuuteen varautuminen
- Skaalautuvuus: kapasiteetin laajennus/supistus modulaarisesti.  
- Teknologian kehittyminen: joustavat tilat, helppo huollettavuus ja päivitettävyys.  
- Sääntelyn muutokset: mittarointi ja raportointi mahdollista tulevia vaatimuksia varten.  
- Pitkän aikavälin suunnittelu yhdistää ympäristövastuun, jatkuvan kehityksen ja muutoskyvyn.

## Tuotokset
- Elinkaarisuunnitelma: vaiheet, aikataulu, riippuvuudet.  
- Rooli- ja vastuumatriisi: suunnittelu–rakentaminen–operointi–raportointi.  
- Modernisointipolku: päivityssyklit, kapasiteetin muutokset, vaikutus mittareihin.  
- Käytöstäpoisto- ja kierrätyssuunnitelma: datahävitys, materiaalivirrat, toimittajaketju.  

## Lähteet
1. Viittaukset ja käytetyt standardit ja oppaat (esim. Schneider Electric 2020).

# 5. Datakeskuksen toiminta vaiheittain

Tässä luvussa kuvataan datakeskuksen energian kulku vaiheittain: sähköverkosta palvelimille, digitaalisten palvelujen muodossa käyttäjille, ja lopulta lämmöksi ulos. Ketju jaetaan seuraaviin osiin: sähkönsyöttö (P5.2), palvelimet ja tallennus (P5.3), jäähdytys (P5.4), verkko (P5.5), hukkalämmön talteenotto (P5.6) ja mittaus/ohjaus (P5.7).

## 5.1 Sähköstä palveluksi

Datakeskus muuntaa saapuvan sähköenergian IT-palveluksi ja lämmöksi. Sähköverkosta sähkö johdetaan muuntajien, UPS-järjestelmien ja jakelukeskusten kautta palvelinsaleihin. Palvelimet käsittelevät dataa, verkkolaitteet välittävät sen käyttäjille, ja lähes kaikki kulutettu sähkö muuttuu lopulta lämmöksi. Jäähdytys poistaa lämmön ja mahdollistaa sen hyötykäytön. Mittaus ja automaatio optimoivat ketjun tehokkuutta.

## 5.2 Sähkönsyöttö ja jakelu

- **Muuntajat:** Kytketään kantaverkkoon, muuntavat korkeajännitteisen sähkö 400 V kolmivaihesähköksi, N+1-redundanssi.  
- **Pääkeskus ja UPS:** UPS tasoittaa jännitepiikit ja katkokset, voi olla online tai line-interactive, hyötysuhde 90–99 %.  
- **Jakelukeskukset ja PDU:** Jakavat sähköä palvelinkaapeille, älykkäät PDU:t mahdollistavat laitekohtaisen seurannan ja ohjauksen.  
- **Varavoima:** Diesel- tai kaasugeneraattorit turvaavat pitkät sähkökatkot, testaus ja optimointi vihreän näkökulman mukaan.

## 5.3 Palvelimet ja tallennus

- **Fyysiset palvelimet:** Räkkikaappeihin asennettuja, korkea tehotiheys säästää tilaa mutta vaatii jäähdytystä. Käyttöasteen optimointi ja virransäästöominaisuudet vähentävät hukkaa.  
- **Virtuaalipalvelimet ja kontit:** Mahdollistavat korkeamman käyttöasteen ja energiatehokkuuden. Orkestraation optimointi tärkeää.  
- **Tallennusratkaisut:** Kiintolevyt, SSD, SAN/NAS ja pilvitallennus. Tiered storage ja erasure coding vähentävät energiankulutusta ja laitekustannuksia.

## 5.4 Jäähdytys ja lämpötilanhallinta

- Jäähdytys ylläpitää lämpötilaa ja kosteutta ASHRAE-suositusten mukaisesti (18–27 °C).  
- Kylmä/kuuma-käytävä, puhallin- ja venttiilisäätö sekä vapaajäähdytys minimoivat energiankulutuksen.  
- Tekoäly voi optimoida jäähdytyksen operointia kuormituksen ja olosuhteiden perusteella.

## 5.5 Verkkoyhteydet ja palvelupyyntöjen käsittely

- Verkkolaitteet (kytkimet, reitittimet, palomuurit) kuluttavat 5–10 % datakeskuksen sähköstä.  
- Palvelupyyntö kulkee palomuurin, kuormantasaimen ja palvelimen kautta takaisin käyttäjälle.  
- Energiatehokkuus saavutetaan yksinkertaisella, oikein mitoitettuna verkkoarkkitehtuurilla ja hallitulla resurssien käytöllä.

## 5.6 Hukkalämmön talteenotto

- Jäähdytyksestä kerätty lämpö siirretään vesikiertoiseen piiriin ja tarvittaessa lämpöpumpulla nostetaan käyttökelpoiseksi.  
- Lämpö voidaan ohjata kaukolämpöön tai paikallisiin kohteisiin.  
- Mittaus ja ohjaus mahdollistavat tehokkaan hyödyntämisen, huomioiden kysynnän vaihtelut ja energiatehokkuuden.

## 5.7 Energian kulutus, mittaus ja ohjaus

- Mittauksella seurataan IT-kuormaa, infrastruktuuria, UPS- ja generaattorihäviöitä sekä hukkalämmön talteenottoa.  
- DCIM- ja BMS-järjestelmät sekä pilvipalvelut kokoavat ja visualisoivat dataa.  
- Tunnusluvut: PUE, ERF, REF, WUE.  
- Mittausdata ohjaa automaatiota ja tekoälypohjaista optimointia, mahdollistaa energian johtamisen resurssina.

## 5.8 Ketjun kooste

Datakeskuksen toiminta voidaan kuvata energian suljettuna ketjuna: sähkö → palvelimet → verkko → jäähdytys → hukkalämpö. Jokainen vaihe vaikuttaa tehokkuuteen: sähkö kulkee häviöttömästi, palvelimet hyödyntävät energiaa laskentaan, verkko kuljettaa dataa optimaalisesti, jäähdytys kuluttaa minimimäärän ja hukkalämpö hyödynnetään. Mittaus ja automaatio varmistavat vihreän operoinnin ja jatkuvan parantamisen.

# 6. Energian kulutus ja uudelleenkäyttö

**Tavoite:** Kuvata datakeskuksen energiankulutuksen lähteet, käyttökohteet ja päästövaikutukset sekä hukkalämmön hyödyntämisen potentiaali.

---

## 6.1 Energiankulutuksen jakautuminen

Datakeskuksen sähkönkulutus jakautuu pääosin IT-laitteisiin, jäähdytykseen, verkkolaitteisiin ja sähkönsyötön tukijärjestelmiin. Karkeasti:  

- **Palvelimet (CPU, RAM, tallennus, emolevyt):** 50–70 %  
- **Jäähdytysjärjestelmät:** 15–30 % (vaihtelee ilmaston ja kuorman mukaan)  
- **Sähkönsyötön tukijärjestelmät (UPS, muuntajat, PDU):** 5–10 %  
- **Verkkolaitteet:** 5–10 %  

**Huom:** Osakuormalla suhteelliset osuudet voivat muuttua, mikä vaikuttaa PUE-arvoon.

### 6.1.1 Prosessorit (CPU)
- Kulutus 25–40 % palvelimen tehosta.  
- Virranhallinta (P- ja C-tilat) säästää energiaa kuorman laskiessa.  
- Konsolidointi ja virtualisointi vähentävät turhaa kulutusta.

### 6.1.2 Muisti (RAM)
- Kuluttaa ~20–30 % palvelimen tehosta.  
- Kulutus riippuu moduulien määrästä, aktiivisuudesta ja virransäästöominaisuuksista.  
- Ylimitoitettu muisti lisää jatkuvaa pohjakulutusta.

### 6.1.3 Virtalähteet (PSU)
- Muuntavat AC:n DC:ksi, häviö ~5–10 %.  
- Hyötysuhde paras 50–70 % kuormalla, huono alhaisella kuormalla.  
- Optimointi: korkealuokkaiset PSU:t ja oikea kuormitus.

### 6.1.4 Verkkolaitteet
- Tyypillisesti ~5 % datakeskuksen energiasta.  
- Kulutus melko riippumatonta dataliikenteestä → pohjakulutus.  
- Optimointi: tarpeen mukaan käytössä olevat portit ja energiatehokkaat laitteet.

### 6.1.5 Tehonhallinta ja UPS
- Kulutus 10–12 %, sisältäen muuntajien, tasasuuntaajien ja akkujen häviöt.  
- Eco-mode ja DC-jakelu vähentävät häviöitä.  
- Varavoimageneraattorit vaikuttavat päästöihin testiajossa ja katkoksissa.

---

## 6.2 Jäähdytyksen energiankulutus
- Toiseksi suurin kuluttaja IT:n jälkeen, 10–30 %.  
- Vaihtelee ilmaston, suunnittelun ja kuorman mukaan.  
- Optimointi: vapaajäähdytys, korkeammat lämpötila-asetukset, hälytys- ja ohjausjärjestelmät.

---

## 6.3 Energia, kWh ja päästöt
- 1 kWh = 1 kW tehoa 1 tunnissa.  
- Datakeskuksen energia muuttuu lähes täysin lämmöksi.  
- Päästöt määräytyvät sähkön tuotannon mukaan: esim. 0,2 kg CO₂/kWh EU-sähköllä.  
- Energiatehokkuus = vähemmän kWh per IT-suorite.

---

## 6.4 Hiilidioksidipäästöjen synty
- Riippuu kulutetusta sähköstä ja sen tuotantotavasta.  
- Fossiilinen sähkö → korkeat päästöt, uusiutuva → lähes nolla.  
- Päästöjä voi vähentää: energiansäästö + uusiutuvan energian käyttö.

---

## 6.5 Vihreä datakeskus ja energiatehokkuus
- **Laitteistot:** energiatehokkaat CPU:t, RAM, UPS ja jäähdytys.  
- **Ohjelmisto:** optimointi vähentää CPU- ja muistikäyttöä.  
- **Kapasiteetin hallinta:** käyttöasteiden optimointi, virtualisointi ja resurssien konsolidointi.  
- **Seuranta ja jatkuva parantaminen:** PUE, lämpötilat, laitehäviöt, PDCA-malli.

---

## 6.6 Hukkalämmön potentiaali
- Lähes kaikki syötetty energia muuttuu lämmöksi.  
- ERF (Energy Reuse Factor) kertoo, kuinka paljon hukkalämpöä hyödynnetään.  
- Hyödyntämällä 50–100 % hukkalämmöstä voidaan merkittävästi parantaa energiataseita ja vähentää primäärienergian tarvetta.  
- Talteenotto riippuu käytännön sopimuksista ja alueellisesta infrastruktuurista.

---

## 6.7 Esimerkkilaskelmia

| Esimerkki | IT-kuorma | PUE | Kokonaiskulutus | Vuotuinen kulutus | CO₂ (0,2 kg/kWh) | ERF |
|-----------|-----------|-----|----------------|-----------------|-----------------|-----|
| Keskikokoinen | 500 kW | 1.3 | 650 kW | 5,7 GWh | 1 140 t | 8 % |
| Hyperscale | 20 MW | 1.15 | 23 MW | 201 GWh | 100 500 t | 50 % |
| Reunadatakeskus | 50 kW | 1.8 | 90 kW | 0,79 GWh | 158 t | - |

- Suurissa yksiköissä pienet tehokkuusparannukset säästävät valtavasti energiaa ja päästöjä.  
- Pienissä yksiköissä korkea PUE suhteellisesti tehoton.  
- Hukkalämmön talteenotto usein tehokkain toimenpide päästöjen vähentämiseen.

# 7. Datakeskusten energiatehokkuuden mittaaminen, sääntely ja keskeiset tunnusluvut

Tässä luvussa käsitellään datakeskusten energiatehokkuuden mittareita, niiden taustaa, datalähteitä, standardeja, sääntelyä ja mittareiden hyödyntämistä johtamisessa ja optimoinnissa.

## 7.1 EN 50600-4 -sarjan rooli

- EN 50600-4 tuo yhtenäisyyttä datakeskusten energiatehokkuuden mittaukseen.
- Määrittelee mittauspisteet, rajaukset ja laskentatavat (PUE, CUE, WUE, REF, ERF).
- Mahdollistaa vertailtavuuden, sisäisen kehityksen seurannan ja toimittajien vertailun.
- Ei aseta tavoitetasoja, vaan standardisoi mittaamisen.

## 7.2 Keskeiset mittarit

- **PUE (Power Usage Effectiveness)**: kokonaiskulutus / IT-kulutus, mittaa infrastruktuurin energiatehokkuutta.
- **WUE (Water Usage Effectiveness)**: veden kulutus / IT-kulutus, huomioi jäähdytyksen vesikäytön.
- **CUE (Carbon Usage Effectiveness)**: päästöt / IT-kulutus, huomioi sähkön päästökerroin.
- **ERF (Energy Reuse Factor)**: hyödynnetty energia / kokonaiskulutus, mittaa hukkalämmön hyödyntämistä.
- **REF (Renewable Energy Factor)**: uusiutuvan energian osuus / kokonaiskulutus.
- PUE, WUE, CUE, ERF ja REF muodostavat kokonaiskuvan energian, veden, päästöjen ja uusiutuvan osuuden hallinnasta.

## 7.3 Mittareiden datalähteet

- **Sähkönkulutus**: päämittarit, PDU-mittaukset, UPS-lähdöt.
- **Vedenkulutus**: vesimittarit jäähdytyksessä, lokit.
- **Automaation järjestelmät**: BMS/DCIM kerää lämpötila-, kuorma- ja laitetiedot.
- **Energiantuotannon tiedot**: sähkön päästökertoimet ja uusiutuvan energian todistukset.
- Mittauspisteet ja tarkkuus suunnitellaan alusta asti, jotta PUE/WUE/CUE-laskelmat ovat luotettavia.

## 7.4 Ympäristöstandardit ja sertifioinnit

- **ISO 50001**: energianhallinnan johtamisjärjestelmä PDCA-syklillä.
- **LEED/BREEAM**: rakennusten ympäristöluokitus, huomioi energia, vesi ja materiaalit.
- **ISO 14001 ja ISO 14064-1**: ympäristöjohtaminen ja päästöraportointi.
- **EU Code of Conduct & Climate Neutral Data Centre Pact**: energiatehokkuuden ja hiilineutraaliuden tavoitteet.

## 7.5 Lainsäädäntö ja raportointivaatimukset

- **EU:n energiatehokkuusdirektiivi (EED 2023/1791)**: vaatii energiasuorituskyvyn raportoinnin yli 500 kW IT-teholla.
- Delegoitu asetus 2024/1364 määrittelee KPI:t ja raportointiaikataulut.
- Yritystason raportointi CSRD:n ja GRI:n mukaisesti.
- Vaatimukset huomioitava jo suunnitteluvaiheessa (mittauspisteet, energiaratkaisut, hukkalämpö).

## 7.6 Mittarit johtamisen ja raportoinnin välineinä

- Mittareilla ohjataan jatkuvaa parantamista, ei pelkkää raportointia.
- Tavoitteiden asettaminen ja säännöllinen seuranta.
- Tulosten visualisointi eri sidosryhmille (tekniset tiimit, johto, asiakkaat).
- Reagointi poikkeamiin ja PDCA-syklin mukainen jatkuva parantaminen.
- Mittarit liitetään johdon päätöksentekoon ja operatiiviseen johtamiseen.

## 7.7 Mittareiden hyödyntäminen kehittämisessä ja optimoinnissa

- Priorisointi: energiankulutuksen ja tehokkuuden heikoimmat kohdat tunnistetaan mittareiden avulla.
- Investointien tuki: mittausdata mahdollistaa energian, kustannusten ja päästöjen arvioinnin.
- Hukkalämmön hyödyntäminen ja uusiutuvan energian optimointi perustuvat tuntitasoiseen dataan.
- Hyötykäytön periaatteet:
  1. Mittaa kattavasti ja tarkasti.
  2. Visualisoi ja analysoi.
  3. Perustele muutokset datalla.
  4. Seuraa vaikutus.
  5. Toista sykli jatkuvasti.
- Yhdistämällä EN 50600, ISO-johtamisjärjestelmät ja EU-raportointi syntyy yhtenäinen malli, jossa kehittäminen perustuu mitattuun tietoon.

---

Lähteet ja standardiviitteet: Maurer et al. 2000; Masanet et al. 2020; Andrae & Edler 2015; Manganelli et al. 2021; Digital Infra 2021; InfoQ 2022; Whitney & Delforge 2014; Datacenter Review 2024; EdTech Magazine 2024; Datacenter Dynamics 2023; Schneider Electric 2015; Google 2016; Datacenter Knowledge 2024; Jin et al. 2016.

