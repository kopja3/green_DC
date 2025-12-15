# Vihreän datakeskuksen suunnittelu- ja toteutusprosessi Suomessa

Alla oleva rakenne on tarkoitettu suoraan oppaan luvuiksi.  
Jokainen vaihe voidaan nostaa omaksi luvukseen tai alaluvuksi (esim. “3.1 Vaihe 1 – Hankepäätös” jne.).

---

## Vaihe 1 – Hankepäätös: Kannattaako oma datakeskus?

**Tavoite**

Päätetään, onko oman (vihreän) datakeskuksen rakentaminen Suomessa perusteltua vai olisiko järkevämpää hyödyntää pilvipalveluja, co-locationia tai hybridiratkaisua.

**Keskeinen sisältö (tutkimusten pohjalta)**

Tutkimuskirjallisuus korostaa, että suurin ympäristöhyöty syntyy, kun:

- vältetään ylikapasiteettia ja nostetaan **palvelimien hyötykäyttöastetta**  
- minimoidaan datakeskuksen **elinkaaren aikainen energiankulutus ja päästöt**  
- yhdistetään datakeskuksen lämpö **paikalliseen lämmöntarpeeseen**.

Suurille hyperskaalaajille oma datakeskus on taloudellisesti järkevä, kun taas pienille toimijoille vihreä ratkaisu voi olla myös “ei rakenneta uutta, käytetään olemassa olevaa kapasiteettia”.

**Tarkistuslista sähköalan ammattilaiselle**

- [ ] Onko IT-kuorma arvioitu realistisesti (kW, kW/räkki, kasvu 5–10 v)?  
- [ ] Onko arvioitu, paljonko kapasiteettia voidaan hankkia pilvestä tai co-location-palveluna?  
- [ ] Onko määritelty kriittisyysluokka (SLA, sallitut katkajat, Tier-taso)?  
- [ ] Onko laskettu karkea **OPEX**-vertailu eri vaihtoehdoille (oma keskus vs. ulkoistus)?  
- [ ] Onko arvioitu hiilijalanjälki (CUE) eri vaihtoehdoille Suomen sähköntuotannon profiililla?  
- [ ] Onko tunnistettu paikalliset kumppanit hukkalämmön hyödyntämiseen (kaukolämpö, tehdas, kasvihuone tms.)?  
- [ ] Onko päätetty, mikä on datakeskuksen tavoite: kustannusoptimointi, huoltovarmuus, hukkalämpöhyöty, tutkimus/HPC tms.?  

---

## Vaihe 2 – Sijainnin valinta Suomessa

**Tavoite**

Valitaan tontti ja liittymät siten, että energiatehokkuus, päästöprofiili ja hukkalämmön hyödyntäminen ovat pitkällä aikavälillä mahdollisimman hyvät.

**Keskeinen sisältö (tutkimusten pohjalta)**

Tutkimuksissa toistuu neljä avaintekijää:

1. **Sähköverkon kapasiteetti ja luotettavuus**  
   – sijainti lähellä vahvaa 110/20 kV -asemaa, mahdollisuus kahteen syöttöön.

2. **Sähkön päästöintensiteetti ja uusiutuvan energian saatavuus**  
   – mahdollisuus pitkäaikaisiin PPA-/alkuperätakuusopimuksiin ja tarvittaessa omaan tuuli/aurinkovoimaan.

3. **Ilmasto ja free cooling**  
   – Suomessa lähes kaikkialla voidaan hyödyntää pitkää free cooling -kautta, mutta viileämmät alueet parantavat tilannetta entisestään.

4. **Hukkalämmön hyödyntäminen**  
   – yhteys kaukolämpöverkkoon tai muuhun lämpöä hyödyntävään toimijaan on vihreän datakeskuksen keskeinen kilpailuetu.

**Tarkistuslista sähköalan ammattilaiselle**

- [ ] Onko tarkistettu alueen 110/20 kV -aseman vapaa kapasiteetti ja laajennusmahdollisuus?  
- [ ] Onko määritelty, tarvitaanko 2N- vai N+1-syöttö (yksi vai kaksi riippumatonta verkkoa)?  
- [ ] Onko sähköverkkoyhtiöltä saatu alustavat liityntä- ja tehomaksut?  
- [ ] Onko kartoitettu paikalliset uusiutuvan energian tuottajat ja PPA-mahdollisuudet?  
- [ ] Onko selvitetty, paljonko free cooling -tunteja sijainti tarjoaa vuodessa (ulkolämpötila + kosteus)?  
- [ ] Onko kaukolämpöyhtiön kanssa käyty läpi lämpötila- ja tehovaatimukset hukkalämmölle?  
- [ ] Onko huomioitu maaperä, tulvariskit, kaavoitus ja logistinen saavutettavuus (huolto, diesel, varaosat)?  
- [ ] Onko tietoliikenneyhteyksille kaksi riippumatonta reittiä (kuitu/väylä)?  

---

## Vaihe 3 – Konseptisuunnittelu: sähkö, energia ja kapasiteetti

**Tavoite**

Määritellään sähkönjakelun ja jäähdytyksen perusarkkitehtuuri, IT-kapasiteetin mitoitus ja vihreät tavoitteet (PUE, CUE, WUE).

**Keskeinen sisältö (tutkimusten pohjalta)**

Tutkimusten mukaan vihreä datakeskus syntyy, kun:

- kapasiteetti **jaetaan modulaarisiin lohkoihin** (esim. 0,5–1 MW), joita voi lisätä kuorman kasvaessa  
- käytetään **energiatehokkaita muuntajia, UPS-järjestelmiä ja PDU:ita** (korkea hyötysuhde myös osakuormalla)  
- suunnitellaan jäähdytys ratkaisuksi, ei “lisäpalikaksi” (free cooling, lämpöpumput, lämpötilatasot)  
- asetetaan selkeät numeeriset tavoitteet: PUE, uusiutuvan energian osuus, hukkalämmön hyödynnetty osuus.

**Tarkistuslista sähköalan ammattilaiselle**

- [ ] Onko määritelty tavoite-PUE (esim. 1,1–1,2 Suomen oloissa)?  
- [ ] Onko määritelty tavoite-CUE (gCO₂/kWh IT-energiaa) sähköntuottajilta saatujen päästökertoimien perusteella?  
- [ ] Onko jaettu datakeskus modulaarisiin sähkö- ja jäähdytyslohkoihin, joita voidaan ottaa käyttöön vaiheittain?  
- [ ] Onko valittu UPS-arkkitehtuuri (N+1, 2N, ring bus tms.) ja varmistettu korkea hyötysuhde 30–80 % kuormilla?  
- [ ] Onko huomioitu mahdollisuus käyttää UPS-akkuja myös tehopiikkien leikkaamiseen (power capping, demand response)?  
- [ ] Onko jäähdytyskonsepti (ilma / vesi / neste) sidottu hukkalämmön hyödyntämiskohteen lämpötasoon?  
- [ ] Onko mitoittavat vikaskenaariot (oikosulut, syöttöhäviöt) mallinnettu ja suojaukset suunniteltu niiden mukaan?  
- [ ] Onko konseptisuunnitelmassa varattu tilat mittareille, varastoille ja mahdolliselle tulevalle PV-/akkujärjestelmälle?  

---

## Vaihe 4 – Rakennus, jäähdytys ja hukkalämpö

**Tavoite**

Toteutetaan rakennus, ilmanvaihto ja jäähdytysjärjestelmä siten, että PUE-tavoite ja hukkalämmön hyödyntäminen ovat realistisesti saavutettavissa.

**Keskeinen sisältö (tutkimusten pohjalta)**

Tutkimuksissa korostuvat:

- **free cooling** (indirect/direct), jonka osuus voidaan Suomessa saada hyvin suureksi  
- **kuuma/kylmä käytävä** ja ilmavirran hallinta, joilla minimoidaan oikosulkuvirtausta ja tarpeetonta jäähdytystehoa  
- **korkeammat tuloilman lämpötilat** (ASHRAE-suositusten yläreunoilla), jotta hukkalämmön lämpötila on hyödynnettävissä  
- lämpöpumput tai lämmönvaihtimet, joilla lämpö nostetaan kaukolämpöverkkoon sopivaksi.

**Tarkistuslista sähköalan ammattilaiselle**

- [ ] Onko rakennuksen kuori ja konehuoneet suunniteltu niin, että ilmavirrat ovat hallittuja (containment)?  
- [ ] Onko free cooling -laitteille riittävä tila ja hyvä ilmavirtaus ulkoilmaan?  
- [ ] Onko jäähdytysjärjestelmän pumput ja puhaltimet valittu taajuusmuuttajilla ja hyvällä hyötysuhteella?  
- [ ] Onko tuloilman suunnittelulämpötila asetettu mahdollisimman korkeaksi datalaitteiden speksien puitteissa?  
- [ ] Onko jäähdytysverkkoon integraatio hukkalämpöasiakkaalle suunniteltu (lämpöpumput, lämmönvaihtimet, varavoima)?  
- [ ] Onko varmistettu, että jäähdytysjärjestelmä toimii myös varasyötöillä (generaattorit, UPS), jos kaukolämpö tai verkko häiriintyy?  
- [ ] Onko tehty koekuormitukset (lämpökuormat) ja varmennettu ilmavirtojen ja lämpötilojen jakautuminen mittauksin?  

---

## Vaihe 5 – IT-, verkko- ja kuormanhallinta

**Tavoite**

Varmistetaan, että IT- ja verkkokerros todella tukevat vihreän datakeskuksen tavoitteita: kuorma on mahdollisimman energy-proportional ja verkko kuluttaa mahdollisimman vähän energiaa.

**Keskeinen sisältö (tutkimusten pohjalta)**

Kirjallisuus painottaa:

- **virtualisointia, konttiteknologioita ja orkestrointia**, joiden avulla kuorma voidaan pakata harvemmille palvelimille  
- **sleep-tiloja, DVFS:ää ja power cappingia** palvelin- ja PDU-tasolla  
- **energiatehokkaita verkkotopologioita** ja mahdollisuutta pudottaa linkkien nopeuksia tai sammuttaa portteja osakuormilla.

Sähköammattilaisen rooli on varmistaa, että sähkönsyöttö ja mittarointi tukevat näitä ratkaisuja (esim. PDU-tason mittaus, tehorajat, akkujen käyttö tehopiikkien tasaamiseen).

**Tarkistuslista sähköalan ammattilaiselle**

- [ ] Onko määritelty maksimi kW/räkki ja siihen sopiva syöttö (esim. 2×16 A/230 V, 3×32 A/400 V tms.)?  
- [ ] Onko PDU:t valittu siten, että niissä on etäluettava mittaus (A, kW, kWh, lämpötila)?  
- [ ] Onko sovittu IT-tiimin kanssa, miten power capping -rajat asetetaan ja kuka niitä hallitsee?  
- [ ] Onko UPS-/akkujärjestelmälle määritelty rooli myös tehopiikkien leikkaamisessa (jos verkkoyhtiö veloittaa huipputehosta)?  
- [ ] Onko verkon kytkimille mahdollisuus porttien ja linkkien nopeuden dynaamiseen säätöön (energy efficient Ethernet tms.)?  
- [ ] Onko kuorman priorisointiluokat dokumentoitu (mikä palvelu saa jatkua generaattoreilla/UPS:llä, mikä voidaan ajaa alas)?  

---

## Vaihe 6 – Mittarointi, operointi ja jatkuva optimointi

**Tavoite**

Rakennetaan mittarointi- ja johtamisjärjestelmä (DCIM), jonka avulla datakeskuksen energiatehokkuutta, päästöjä ja käyttöastetta voidaan seurata ja parantaa läpi elinkaaren.

**Keskeinen sisältö (tutkimusten pohjalta)**

Vihreiden datakeskusten kirjallisuus nostaa esiin erityisesti:

- **PUE ja DCiE** – jaottelu IT vs. muu infrastruktuuri  
- **CUE** – CO₂-päästöt suhteessa IT-energiaan  
- **WUE** – veden kulutus  
- **J/bit ja verkon energiankulutus** – kuinka paljon energiaa siirtyy yhtä bittiä kohti.

Kaikissa tutkimuksissa korostuu, että mittarointi pitää suunnitella **sähkö- ja jäähdytysinfran kanssa yhtä aikaa**, ei jälkikäteen.

**Tarkistuslista sähköalan ammattilaiselle**

- [ ] Onko pääsyötössä tarkka energiamittaus (kWh, kW, mahdollisesti 15 min tehoprofiili)?  
- [ ] Onko UPS:ien tulot ja lähdöt mitattu erikseen (hyötysuhteen ja häviöiden seurantaa varten)?  
- [ ] Onko jäähdytysjärjestelmän sähkönkulutus mitattu erikseen (pumput, puhaltimet, kompressorit)?  
- [ ] Onko IT-riveillä tai PDU-tasolla mitattu IT-energia (PUE-laskentaa varten)?  
- [ ] Onko mittaukset integroitavissa DCIM-/monitorointijärjestelmään (API, Modbus, BACnet tms.)?  
- [ ] Onko määritelty raportointitaajuus ja vastuut (kuka seuraa PUE:ta, kuka CUE:ta, kenelle raportoidaan)?  
- [ ] Onko sovittu vuosittaiset tai puolivuosittaiset “optimointikierrokset”, joissa tarkastellaan mittareita ja suunnitellaan parannuksia?  

---

## Vaihe 7 – Elinkaari, modernisointi ja kiertotalous

**Tavoite**

Hallitaan laitteiden ja infrastruktuurin koko elinkaari suunnittelusta purkuun niin, että sekä energia- että materiaalivirrat ovat mahdollisimman pienipäästöisiä.

**Keskeinen sisältö (tutkimusten pohjalta)**

Tutkimukset ja myös laajempi ICT–ilmasto-kirjallisuus korostavat:

- IT-laitteiden ja akkujen **elinkaari- ja kierrätysnäkökulmaa**  
- tarvetta **suunnitella päivityssyklit** (esim. 3–5 vuoden välein tehokkaammat palvelimet → sama palvelu pienemmällä teholla)  
- varastointijärjestelmien (akut, FES, lämpövarastot) syklimäärän ja ikääntymisen huomiointia mitoituksessa  
- mahdollisuutta siirtää osa kuormasta tulevaisuudessa vähäpäästöiseen pilveen tai toisiin keskuksiin.

**Tarkistuslista sähköalan ammattilaiselle**

- [ ] Onko laadittu elinkaarisuunnitelma kunkin kriittisen järjestelmän osalta (muuntajat, UPS, akut, generaattorit, jäähdytys)?  
- [ ] Onko arvioitu akkujen ja mahdollisten muiden varastojen syklimäärä ja vaihtoajankohta sekä niiden ympäristövaikutukset?  
- [ ] Onko sovittu kierrätys- ja jälleenkäyttöprosessit (esim. valmistajan take-back, sertifioitu kierrättäjä)?  
- [ ] Onko määritelty, milloin vanhan konesalilohkon PUE alkaa olla niin huono, että sen korvaaminen uudella on energiataseen kannalta järkevää?  
- [ ] Onko valittu laite- ja kaapelointikomponentteja, joilla on riittävä lämpö- ja kuormankesto koko suunnitellulle elinkaarelle?  
- [ ] Onko dokumentaatio (yksilöinti, piirustukset, kuormitusraportit) ylläpidetty niin, että purkuvaiheessa tiedetään, mitä puretaan ja minne se ohjataan?  

---

Tämän rungon voi nyt liittää osaksi oppaan yleistä rakennetta (esim. “3. Vihreän datakeskuksen toteutus Suomessa”) ja täydentää jokaista vaihetta yksityiskohtaisemmilla esimerkeillä, kaavioilla ja viittauksilla jo tekemääsi kirjallisuuskatsaukseen.
