# ✅ Vastausliite: Itseopiskelutehtävät – Vihreä datakeskus

Tämä liite sisältää suuntaa‑antavat, oikeiksi katsottavat vastaukset tehtäviin. Niitä voi käyttää itsearviointiin tai keskustelun pohjaksi.

> **Huom.** Vastaukset ovat tiiviitä. Opettaja tai ohjaaja voi täydentää esimerkein tai ajankohtaisin luvuilla.

---

## 🔹 Moduuli 1 – Vihreän datakeskuksen elementit ja periaatteet

| Kohta | Mallivastaus |
|-------|--------------|
| **Palvelimet** | Suorittavat sovellusten laskentatehtävät. Energia kuluu prosessoreihin, muisteihin, levyihin ja tuulettimiin; kaikki muuttuu lopulta lämmöksi. |
| **Verkkolaite** | (Kytkin/reititin) välittää paketit palvelimilta internetiin ja takaisin; energia kuluu ASIC‑piireihin ja signaalien vahvistamiseen. |
| **Jäähdytys (ilma)** | Kylmä ilma johdetaan laitekaappien eteen → kuuma ilma poistuu hot‑aislesta → CRAC‑/CRAH‑yksiköt jäähdyttävät → lämpö luovutetaan kompressorien/kuivapuhaltimien kautta ulos. |
| **Jäähdytys (neste)** | Vesi/glykoliliuos kiertää kuparilevyjen tai cold plate ‑ratkaisujen kautta → siirtää lämmön lämmönvaihtimeen → lämpö voidaan käyttää kaukolämpöön. >45 °C lämpötila sopii suoraan lämpöpumppuihin tai matalan verkon syöttöön. |
| **Hukkalämmön hyödyntäminen** | Kaukolämpöverkko, käyttöveden esilämmitys, kasvihuoneiden lämmitys, prosessilämmitys, jäähdytys lämmöntalteenottokoneella. |
| **Uusiutuva sähkö** | Aurinko, tuuli, vesivoima, biomassa, ydinvoima vähähiilisyytenä. Etu: pienempi CO₂‑jalanjälki ja usein ennustettavampi hinta. |
| **Kylmä ilmasto** | Mahdollistaa free coolingin suuren osan vuodesta ⇒ kompressorijäähdyttimien käyttö vähenee ⇒ PUE pienenee. |
| **Modulaarinen rakenne** | Laitteet/laitekaapit voidaan lisätä tai vaihtaa ilman koko salin remonttia; vähentää ylisuurta kapasiteettia ja mahdollistaa energiatehokkuuden optimoinnin elinkaaren aikana. |

---

## 🔹 Moduuli 2 – Datakeskuksen elinkaaren vaiheet

| Vaihe | Ympäristöön vaikuttava päätösesimerkki |
|-------|----------------------------------------|
| **Suunnittelu** | Sijainti lähellä uusiutuvaa sähköä ja kaukolämpöverkkoa. |
| **Rakentaminen** | Kierrätettävät rakennusmateriaalit, energiatehokkaat UPS‑ratkaisut. |
| **Käyttö** | Jäähdytyksen optimointi, energianseuranta, virtualisointi. |
| **Ylläpito** | Komponenttien vaihto energiatehokkaampiin versioihin. |
| **Purku** | Laitteiden ja materiaalien kierrätys, vaarallisten aineiden asianmukainen käsittely. |

**Kiertotalous – esimerkkivaihe:** Purku: laitteet puretaan ja osat (kupari, kulta, alumiini) kierrätetään, runkorakenteet murskataan uusiokäyttöön.

**Tärkein vaihe vihreyden kannalta (esimerkki‑perustelu):** Suunnittelu, koska siinä lukitaan suurin osa energiankulutukseen ja sijaintiin liittyvistä ratkaisuista (sähkölähde, jäähdytyskyky, hukkalämmön hyödyntäminen).

---

## 🔹 Moduuli 3 – Datakeskuksen toiminta vaiheittain

**Energian ketju (tekstimuodossa):**
Uusiutuva sähkö → Muuntaja/UPS → Virtalähteet → Prosessorit/Muistit/Levyt → Lämmöksi komponenteissa → Puhaltimet/Nestekierto → Lämmönvaihdin → Kaukolämpö tai ulkoilma.

**Lämpöä eniten tuottavat kohdat:**
1) Prosessorit (CPU/GPU)
2) Virtalähteiden ja UPS:n muuntotappiot.

**Prosessori vs. muisti:** CPU‑sirun tehotyppinen kulutus 150–350 W per paketti; lämpö tiiviillä alueella → korkea lämpötiheys. RAM‑moduulit ~2–10 W/moduuli, lämpö laaja‑alaisempaa; kokonaiskulutus kuitenkin huomattava monella moduulilla.

---

## 🔹 Moduuli 4 – Energian kulutus ja uudelleenkäyttö

1. **PUE‑lasku:**
Kokonaisenergia = IT-energia × PUE = 800 kWh × 1,5 = 1200 kWh/vrk

2. **Nestejäähdytyksen etu:** Suora komponenttikontakti → tehokas lämmönpoisto, korkea menolämpö (>55 °C) → lämpö hyödynnettävissä ilman lisäkompressoria ⇒ parempi ERF.

3. **Fortum/Helsinki‑case:** Datakeskusten jäähdytysvesi kytketään kaukolämpöverkon lämmönvaihtimeen; talteenotettu lämpö kattaa jopa kymmeniä MW, vähentää fossiilista kaukolämpöä (CO₂‑säästö ~20–40 kt/a).

---

## 🔹 Moduuli 5 – EN 50600‑4‑mittarit

| Mittari | Kuvaus |
|---------|--------|
| **PUE** | Total Facility Energy / IT Equipment Energy (≥ 1). |
| **ERF** | Reused Energy / Total Energy (0–1). |
| **CUE** | CO₂‑kg per IT‑kWh (g CO₂/kWh). |
| **WUE** | Veden litrat per IT‑kWh (l/kWh). |

**Tärkein mittari (esimerkkiperustelu):** CUE, koska se korreloi suoraan ilmastovaikutuksen kanssa – mutta valinta riippuu tarkastelun painopisteestä (esim. vesistressi‑alueilla WUE).

**PUE vs. ERF:** Datakeskus, jonka PUE = 2.0 mutta ERF = 0.6 (60 % lämmöstä käytetään hyödyksi), voi kokonaisuutena aiheuttaa vähemmän netto­päästöjä kuin PUE = 1.3 ja ERF = 0 (lämpö puhalletaan ulos).

---

💡 **Muista:** Vastaukset voivat vaihdella hieman lähteistä ja aikaisista luvuista riippuen. Tärkeintä on looginen perustelu ja konseptien ymmärrys.

