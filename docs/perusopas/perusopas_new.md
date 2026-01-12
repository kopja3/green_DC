

### P1.1 Miksi perusopas?

Tämä perusopas tukee vihreän datakeskuksen suunnittelua ja toteutusta Suomessa. Opas jäsentää keskeiset päätökset vaiheisiin ja kytkee ne mitattaviin suureisiin: **energia (E), teho (P), kapasiteetti (C)** ja **palvelutaso (SLA)** (Uddin & Rahman, 2012; Geng, 2015; Jin et al., 2016). Keskeinen periaate on, että jokainen “vihreyttä” koskeva väite voidaan palauttaa **mittausrajaan**, **mittauspisteisiin** ja **laskentasääntöön**.

Opas etenee seuraavasti:

* **Luku 2: Miksi datakeskus rakennetaan ja miten sijainti valitaan**
  Sijainnin reunaehdot: sähkö, verkko, viive, jäähdytys sekä hukkalämpöliitynnät.

* **Luku 3: Vihreän datakeskuksen peruselementit ja periaatteet**
  Osa-alueet ja käsitteet, joilla vihreyttä tarkastellaan; mittausrajat ja arvioinnin periaatteet.

* **Luku 4: Datakeskuksen elinkaaren vaiheet**
  Suunnittelu, rakentaminen, käyttö ja käytöstäpoisto; data- ja materiaalivirrat.

* **Luku 5: Datakeskuksen toiminta vaiheittain**
  Kuorma ja palvelutaso → kapasiteettisuunnittelu → IT-teho ajan funktiona → sähkö- ja jäähdytysinfrastruktuurin mitoitus.

* **Luku 6: Energian kulutus ja uudelleenkäyttö**
  Kulutuserät, jäähdytyksen sähkönkulutus, hukkalämmön talteenotto, rajapinnat ja mittaustieto.

* **Luku 7: Energiatehokkuuden mittaaminen**
  EN/ISO/IEC 30134 -mittarit ja mittauspisteet; mittarikortit (PUE, REF, ERF, CER, CUE, WUE).

Oppaan merkinnät ja mitoitusketjun symbolit esitellään kohdassa **P1.4**.

---

### P1.2 Mikä on vihreä datakeskus?

Tässä oppaassa **vihreä datakeskus** tarkoittaa datakeskusta, jossa suunnittelu ja operointi sidotaan **energian käytön mittaamiseen**, **energiatehokkuusmittareihin** ja **päästöintensiteetin raportointiin** (Uddin & Rahman, 2012; Jin et al., 2016; Geng, 2015). “Vihreys” ei ole yksittäinen tekninen ratkaisu, vaan päätösten ketju, jonka vaikutus voidaan todentaa datasta.

Vihreä datakeskus tarkastellaan seuraavina osa-alueina:

* **Kuorma ja kapasiteetti:** työkuorman kuvaus, kapasiteetin mitoitus ja IT-tehon vaihtelu ajassa.
* **Sähkönsyöttö ja varmistus:** sähköliittymä, jakelu, UPS/varavoima ja häviöt.
* **Sähkön alkuperä ja päästöt:** hankintatapa, todentaminen ja päästökertoimet raportointiin.
* **Jäähdytys:** jäähdytysarkkitehtuuri ja jäähdytyksen sähkönkulutus suhteessa IT-tehoon.
* **Hukkalämpö:** talteenotto, mittaus ja luovutusrajapinta.
* **Elinkaaren loppu:** käytöstäpoisto, tietojen hävittäminen ja materiaalivirrat.

Osa-alueiden päätökset kuvataan kohdassa **P1.8**, ja tekninen toteutus avataan luvussa **3**.

---

### P1.3 Miten opasta käytetään?

Opas on kirjoitettu päätöksenteon ja dokumentoinnin tueksi. Käytä sitä niin, että etenet aina **kysymyksestä päätökseen** ja päätöksestä **mitattaviin lähtötietoihin**.

1. **Määritä lähtötiedot ja rajaukset.**
   Kirjaa työkuorman ja palvelutason vaatimukset sekä mittausrajat (mistä kokonaisenergia mitataan ja mistä IT-energia rajataan).

2. **Johda mitoitusketju.**
   Johda työkuormasta kapasiteetti ja IT-tehon vaihtelu ajassa, ja mitoita niiden perusteella sähköliittymä, jakelu, varmistus ja jäähdytys (merkinnät ja suureet kohdassa **P1.4**).

3. **Valitse mittarit ja todentaminen.**
   Valitse energiatehokkuus- ja päästömittarit, määritä mittauspisteet ja dokumentoi sähkön alkuperän todentaminen sekä päästökertoimet raportointia varten.

Kun toteutus on käynnissä, käytä toimintamallia: **mittaa → analysoi → muutos → todenna → vakioi**.

---




