## 2. Datakeskuksen elinkaaren vaiheet

Datakeskuksen elinkaari muodostuu kuudesta päävaiheesta, jotka kattavat koko prosessin tarpeen tunnistamisesta aina käytöstä poistoon ja uudelleenkäyttöön asti.

Klikkaamalla alla olevia otsikoita voit tarkastella kutakin vaihetta erikseen.

---

<details>
<summary>🔢 Vaihe 1: Tarvekartoitus ja esiselvitys</summary>

![Vaihe 1](kuvat/Vaihe1.png)

Tässä tärkeässä alkuvaiheessa laaditaan perusta koko datakeskuksen kehittämiselle. Tarkoitus on luoda kokonaisvaltainen ymmärrys hankkeen toteutettavuudesta ja ympäristövaikutuksista. Vaihe sisältää viisi keskeistä osa-aluetta:

1. **Riskianalyysi** – arvioidaan sekä tekniset (esim. järjestelmien luotettavuus), taloudelliset (budjetointi, ROI) että ympäristöriskit (esim. maaperän tila, sään ääri-ilmiöt).  
2. **Kapasiteetin tarve** – määritellään tarvittava laskentateho ja tallennuskapasiteetti nykytilanteeseen ja tulevaisuuden kasvuun perustuen.  
3. **Sijainnin arviointi** – valinta tehdään energian saatavuuden, yhteyksien, logistiikan ja paikallisen infrastruktuurin pohjalta.  
4. **Kustannus–hyötyanalyysi** – vertaillaan investoinnin kokonaiskustannuksia ja pitkän aikavälin hyötyjä, mukaan lukien ympäristöhyödyt.  
5. **Ympäristövaikutusten arviointi** – selvitetään elinkaaren eri vaiheiden vaikutukset, kuten energiankulutus, vedenkäyttö ja hiilijalanjälki.

Tämä vaihe on keskeinen siksi, että pelkkä operatiivisen energian tarkastelu ei riitä; samalla on välttämätöntä huomioida koko elinkaaren ympäristövaikutukset (UNEP DTU, 2020). Lisäksi käytännön konsultointi– ja feasibility-lähteet, kuten Schneider Electricin dokumentti, painottavat, että huolellinen alkuvaiheen analyysi (kuten tarvekartoitus ja sijainnin valinta) on ratkaiseva kokonaiskustannusten sekä projektin aikataulujen hallinnassa (Schneider Electric, 2015).

**Lähteet:**
- UNEP DTU Partnership. (2020). *Environmental sustainability of data centres: A need for a multi-impact and life-cycle approach*. [Linkki](https://c2e2.unepccc.org/wp-content/uploads/sites/3/2020/02/environmental-sustainability-of-data-centres-a-need-for-a-multi-impact-and-life-cycle-approach-brief-1-uk.pdf?utm_source=chatgpt.com)  
- Schneider Electric – Data Center Science Center. (2015). *Fundamentals of Managing the Data Center Life Cycle for Owners*. [Linkki](https://www.insight.com/content/dam/insight-web/en_US/article-images/whitepapers/partner-whitepapers/fundamentals-of-managing-the-data-center-life-cycle-for-owners.pdf?utm_source=chatgpt.com)  

</details>

---

<details>
<summary>🛠️ Vaihe 2: Suunnittelu</summary>

![Vaihe 2](kuvat/Vaihe2.png)

Datakeskuksen suunnitteluvaiheessa tehdään ratkaisevat valinnat, jotka vaikuttavat sekä energiatehokkuuteen että pitkän aikavälin ympäristövaikutuksiin. Kuvastoon on koottu keskeisiä teemoja:

- **Energiatehokkuus** – PUE eli Power Usage Effectiveness on keskeinen mittari, joka kuvaa, kuinka paljon energiaa kuluu IT-laitteiden lisäksi jäähdytykseen ja muuhun infrastruktuuriin. Mitä lähempänä arvo on 1, sitä parempi.  
- **Uusiutuva energia ja hukkalämmön talteenotto** – Suunnittelussa kannattaa huomioida mahdollisuudet käyttää aurinko-, tuuli- tai hukkalämpöenergiaa, mikä vähentää operatiivisia päästöjä ja energian kokonaiskulutusta.  
- **Moniammatillinen tiimityö ja simulointi** – Monialainen yhteistyö (insinöörit, ympäristöasiantuntijat, IT-suunnittelijat) sekä simulointimallit (esim. airflow, energiajärjestelmät) mahdollistavat optimoidut ratkaisut.  
- **Kiertotalous ja elinkaari** – Suunnittelun tulisi huomioida elinkaariajattelu: komponenttien kierrätettävyys, modulaarisuus ja tulevat päivitysmahdollisuudet.

Tieteellinen näkökulma korostaa, että pelkän operatiivisen energiatehokkuuden optimoinnin (kuten alhainen PUE) sijaan suunnittelun tulee ottaa huomioon koko elinkaaren ympäristövaikutukset (Whitehead ym., 2015). Lisäksi parhaat käytännöt (esim. LBNL:n ohjeistus) sisältävät kattavat suositukset ilmastointijärjestelmien, sähkönsyötön, jäähdytyksen ja lämmön talteenoton yhteensovittamisesta energiatehokkuuden parantamiseksi (LBNL, 2025).

**Lähteet:**
- Whitehead, B., Andrews, D., & Shah, A. (2015). *The life cycle assessment of a UK data centre*. *International Journal of Life Cycle Assessment, 20*, 332–349. [Linkki](https://link.springer.com/article/10.1007/s11367-014-0838-7?utm_source=chatgpt.com)  
- Lawrence Berkeley National Laboratory (2025). *Best Practices Guide for Energy-Efficient Data Center Design*. [Linkki](https://datacenters.lbl.gov/sites/default/files/2025-07/best_practice-guide-data-center-design.pdf)


</details>

---

<details>
<summary>⚖️ Vaihe 3: Päätöksenteko ja luvitus</summary>

![Vaihe 3](kuvat/Vaihe3.png)

Tässä vaiheessa tehdään datakeskuksen toteutuksen kannalta ratkaisevat päätökset ja varmistetaan, että hankkeen eteneminen täyttää sekä viranomaismääräykset että kestävän kehityksen tavoitteet. Prosessi on luonteeltaan monivaiheinen ja monialainen, ja siihen sisältyy neljä keskeistä osa-aluetta.

1. **EU- ja kansallisen tason sääntelykehys** – Toimintaa ohjaavat EU:n ja kansallisen tason määräykset. Näistä keskeinen on EU:n teollisuuspäästödirektiivi (*Industrial Emissions Directive*, IED), joka määrittää suurten teollisuuslaitosten – mukaan lukien merkittävästi energiaa kuluttavat datakeskukset – vähimmäistasoiset ympäristönsuojeluvaatimukset. Direktiivin tavoitteena on ehkäistä ja vähentää ilman, veden ja maaperän pilaantumista hyödyntämällä parasta käyttökelpoista tekniikkaa (BAT, *Best Available Techniques*). Kansallinen lainsäädäntö ja energiatehokkuusvaatimukset, kuten energiatodistus ja ympäristö-, terveys- ja turvallisuusstandardit (EHS), täydentävät sääntelykehystä.

2. **Lupaprosessi ja päätöksenteko** – Tähän sisältyvät investointipäätökset, sijainti- ja teknologiavalinnat sekä näihin liittyvien lupahakemusten ja viranomaisdokumenttien valmistelu ja toimittaminen. Prosessiin kuuluu myös kaavoituksen koordinointi.

3. **Infrastruktuurin suunnittelu ja sijainnin määrittely** – Kattaa liittymisen sähköverkkoon ja kapasiteettivaatimusten varmistamisen, tietoliikenneyhteyksien toteutuksen sekä maankäytön ja alueellisen suunnittelun reunaehtojen huomioimisen.

4. **Ympäristövastuu ja vaikutusten hallinta** – Sisältää ilmasto- ja luontovaikutusten arvioinnin sekä sidosryhmien, erityisesti paikallisyhteisöjen, osallistamisen suunnitteluprosessiin. Tässä yhteydessä huomioidaan myös ympäristöluvat ja niihin liittyvät rajoitukset, kuten melu-, vesi- ja ilmanlaadun sääntely.

Tutkimuskirjallisuus korostaa, että elinkaarilähtöinen arviointimalli on välttämätön, jotta päätöksenteossa ei rajoituta pelkästään operatiivisten tavoitteiden optimointiin, vaan huomioidaan myös rakentamisen ympäristökuormitus ja päästöjen seuranta (Tozzi, 2025). Käytännön kokemukset osoittavat, että ympäristölupien – esimerkiksi varavoimajärjestelmien käytön tai päästöjen hallinnan – käsittely vaatii tarkkaa ajoitusta, sillä kaavoitus- ja lupaprosessien viivästykset voivat merkittävästi hidastaa hankkeen etenemistä (RPS, 2025).

**Lähteet:**
- Tozzi, C. (2025, kesä 11). *Data Center Life Cycle Assessments: A New Sustainability Standard*. *Data Center Knowledge*. [Linkki](https://www.datacenterknowledge.com/data-center-construction/data-center-life-cycle-assessments-the-new-sustainability-standard?utm_source=chatgpt.com)  
- RPS Group. (2025). *Environmental permitting for data centres: What you need and when to apply*. [Linkki](https://www.rpsgroup.com/insights/consulting-uki/environmental-permitting-for-data-centres-what-you-need-and-when-to-apply)  


</details>


---

<details>
<summary>🏗️ Vaihe 4: Rakentaminen</summary>

![Vaihe 4](kuvat/Vaihe4.png)

Rakentamisvaihe merkitsee datakeskuksen elinkaaressa siirtymistä suunnitelmista konkreettiseen toteutukseen. Tässä vaiheessa fyysinen infrastruktuuri luodaan, ja sen valinnat vaikuttavat merkittävästi sekä rakennusvaiheen että koko käyttöiän aikaiseen ympäristökuormitukseen. Rakentamisvaihe voidaan jäsentää neljään pääosa-alueeseen:

1. **Rakennustekniset ratkaisut** – Käsittää datakeskusrakennuksen runkorakenteet, kuormat ja modulaarisuuden. Rakennusmateriaalien valinnalla (esim. vähähiilinen betoni, kierrätetyt teräsrakenteet) voidaan vähentää merkittävästi rakentamisen hiilijalanjälkeä (Cooper ym., 2021).

2. **Teknisen infrastruktuurin asennus** – Sisältää sähkö- ja jäähdytysjärjestelmien, varavoimalaitteiden, kaapeloinnin sekä IT-räkkien ja konesalivarusteiden asennuksen. Näiden energiatehokkuus ja huollettavuus vaikuttavat pitkän aikavälin operatiivisiin kustannuksiin ja päästöihin (Shehabi ym., 2016).

3. **Työmaan turvallisuus ja aikataulun hallinta** – Rakentaminen edellyttää tiukkojen turvallisuusstandardien noudattamista sekä tarkkaa projektinhallintaa, jotta aikatauluviiveet eivät johda kustannusten ja ympäristövaikutusten kasvuun.

4. **Käyttöönottovaiheen valmistelu** – Sisältää laitteistojen testaukset, järjestelmien validoinnin ja infrastruktuurin optimoinnin ennen operatiivisen toiminnan aloitusta. Tämä vaihe on kriittinen, jotta suunnitellut energiatehokkuus- ja luotettavuustavoitteet voidaan saavuttaa heti käyttöönotosta lähtien (LBNL, 2025).

Tutkimuskirjallisuuden mukaan rakentamisvaiheen päästöt ja energiankulutus voivat muodostaa huomattavan osuuden koko datakeskuksen elinkaaren ympäristövaikutuksista, erityisesti jos käytetään paljon energiaintensiivisiä materiaaleja ja tekniikoita (Whitehead ym., 2015). Siksi rakennusvaiheen optimointi – esimerkiksi modulaarisen rakentamisen ja uusiomateriaalien avulla – on olennainen osa kestävää datakeskussuunnittelua.

**Lähteet:**
- Cooper, S., Hammond, G., & Norman, J. (2021). *Environmental assessment of building materials and technologies for sustainable data centres*. *Journal of Cleaner Production, 315*, 128172. https://doi.org/10.1016/j.jclepro.2021.128172  
- Shehabi, A., Smith, S., Sartor, D., Brown, R., Herrlin, M., Koomey, J., ... & Lintner, W. (2016). *United States Data Center Energy Usage Report*. Lawrence Berkeley National Laboratory. [Linkki](https://eta.lbl.gov/publications/united-states-data-center-energy)  
- Whitehead, B., Andrews, D., & Shah, A. (2015). *The life cycle assessment of a UK data centre*. *International Journal of Life Cycle Assessment, 20*, 332–349. https://doi.org/10.1007/s11367-014-0838-7  
- Lawrence Berkeley National Laboratory (2025). *Best Practices Guide for Energy-Efficient Data Center Design*. [Linkki](https://datacenters.lbl.gov/sites/default/files/2025-07/best_practice-guide-data-center-design.pdf)

</details>

---

<details>
<summary>🖥️ Vaihe 5: Operatiivinen toiminta</summary>

![Vaihe 5](kuvat/vaihe5_2.png)
</details>

---

<details>
<summary>♻️ Vaihe 6: Käytöstä poisto ja uudelleenkäyttö</summary>

![Vaihe 6](kuvat/Vaihe6.png)
</details>
