

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


P1.4 Merkinnät, symbolit ja yksiköt (sekä mitoitusketju)

Tässä oppaassa “vihreys” palautetaan aina mittausrajaan, mittauspisteisiin ja laskentasääntöön. Siksi merkinnät on koottu tähän: samat symbolit toistuvat mitoituksessa, mittareissa ja raportoinnissa.

Mittausraja ja perusjoukot (käytännön tulkinta)

IT-alue (IT): palvelimet, tallennus, verkkolaitteet (IT Equipment).

Laitosalue (Facility): kaikki IT-alueen lisäksi: sähköjakelu/häviöt, UPS, muuntajat, jäähdytys, pumput/puhaltimet, valaistus ym.

Indeksit/suffiksit:

_IT = IT-alueeseen kuuluva suure

_cool = jäähdytykseen liittyvä

_fac = koko laitoksen (facility) kokonaisuus

_th = lämpöteho / lämpöenergia

| Symboli      | Selite                      |           Yksikkö | Huomio / tyypillinen käyttö                    |
| ------------ | --------------------------- | ----------------: | ---------------------------------------------- |
| **t**        | aika                        |              s, h | käytännössä usein tuntisarja (1 h askel)       |
| **Δt**       | aikaväli                    |              s, h | esim. 1 h mittausjakso                         |
| **P**        | teho                        |         W, kW, MW | hetkellinen / keskiarvo jaksolla               |
| **E**        | energia                     | Wh, kWh, MWh, GWh | (E=\sum P\cdot \Delta t)                       |
| **P_IT(t)**  | IT-teho ajan funktiona      |             kW/MW | kuormaprofiili (mitoitus + vuosikulutus)       |
| **E_IT**     | IT-energia                  |           kWh/MWh | IT-alueen energiankulutus periodilla           |
| **P_cool**   | jäähdytyksen sähköteho      |             kW/MW | chillers, pumput, CRAH/CRAC, puhaltimet        |
| **E_cool**   | jäähdytyksen energia        |           kWh/MWh | (E_{cool}=\sum P_{cool}\Delta t)               |
| **P_fac(t)** | koko laitoksen teho         |             kW/MW | IT + jäähdytys + sähkönsyötön häviöt + muut    |
| **E_fac**    | koko laitoksen energia      |           kWh/MWh | kokonaiskulutus mittausrajassa                 |
| **Q_th(t)**  | lämpöteho (hukkalämpö)      |             kW/MW | tyypillisesti ~ IT-tehon suuruusluokkaa        |
| **E_th**     | lämpöenergia                |   kWh_th / MWh_th | “_th” erottaa sähköstä (kWh_el)                |
| **COP**      | jäähdytyksen hyötysuhdeluku |                 – | (COP=\frac{Q_{removed}}{P_{cool}})             |
| **η**        | hyötysuhde (yleinen)        |                 – | esim. UPS, muuntaja, lämmönsiirto              |
| **C_inst**   | asennettu kapasiteetti      |       kW/MW, rack | maksimi fyysinen/tekninen kapasiteetti         |
| **C_act**    | aktiivinen kapasiteetti     |       kW/MW, rack | käytössä oleva osa C_inst:stä                  |
| **C_res**    | varattu kapasiteetti        |       kW/MW, rack | sopimuksin varattu / reserved headroom         |
| **SLA**      | palvelutaso                 |             – / % | saatavuus, vaste, RTO/RPO ym.                  |
| **PUE**      | Power Usage Effectiveness   |                 – | (PUE=\frac{P_{fac}}{P_{IT}}) (tai energioilla) |
| **WUE**      | Water Usage Effectiveness   |          L/kWh_IT | jos vettä käytetään jäähdytyksessä             |
| **CUE**      | Carbon Usage Effectiveness  |     kgCO₂e/kWh_IT | riippuu päästökertoimista ja rajauksesta       |
| **EF**       | päästökerroin               |        kgCO₂e/kWh | sähkö (markkina-/sijaintiperusteinen)          |



Nopea yksikkömuistutus:
1 kW = 1000 W
1 MWh = 1000 kWh
Vuosienergia tuntisarjasta: 
E_year=∑h=18760P(h)⋅1h E_year=∑ h=1 8760 P(h)⋅1h

(1) Tarve & SLA
    └─> työkuorma (W): palvelut, käyttäjät, datamäärät, AI/CPU/GPU, kasvu
    └─> SLA: saatavuus, vaste, kapasiteettivara, RTO/RPO

(2) Kuorma → IT-kapasiteetti
    └─> C_inst (asennettu): maksimi IT-kapasiteetti (kW/MW tai rackit)
    └─> C_act (aktiivinen): käytössä oleva kapasiteetti
    └─> C_res (varattu): sopimuksin varattu / tuleva kasvu

(3) IT-kapasiteetti → IT-tehoprofiili
    └─> P_IT(t): kuormaprofiili (keskiteho, huiput, vaihtelu)
    └─> mitoittava IT-teho: P_IT,peak (tai N+1 -periaatteella määritelty)

(4) IT-teho → Kokonaisteho ja energiat
    └─> P_fac(t) = P_IT(t) + P_cool(t) + P_losses(t) + P_other(t)
    └─> E_IT  = Σ P_IT(t)·Δt
    └─> E_fac = Σ P_fac(t)·Δt

(5) Jäähdytysmitoitus
    └─> lämpökuorma Q_th(t) ≈ P_IT(t) (+ muut häviöt)
    └─> P_cool(t) = Q_removed(t) / COP(t)
    └─> valinta: jäähdytysarkkitehtuuri, mitoituslämpötilat, redundanssi

(6) Sähkönsyöttö & varmistus
    └─> liittymä + jakelu + UPS/varavoima mitoitetaan P_fac,peak perusteella
    └─> häviöt ja hyötysuhteet (η) kirjataan ja mitataan

(7) Mittarit & todentaminen (raportoitava “vihreys”)
    └─> PUE = P_fac / P_IT  (hetkellinen tai periodin energia)
    └─> CUE = (E_fac · EF) / E_IT  (rajauksesta riippuen)
    └─> WUE, jos relevantti
    └─> mittauspisteet: IT-syötöt, jäähdytyksen syötöt, kokonaismittaus

(8) Hukkalämpö (jos mukana)
    └─> E_th,reused: talteen otettu ja hyödynnetty lämpöenergia
    └─> dokumentoi: rajapinta, mittaus, luovutusehdot ja hyödyntäjä



