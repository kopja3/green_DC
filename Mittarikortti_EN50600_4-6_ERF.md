## EN 50600-4-6 (ERF) – Energy Reuse Factor

**Kategoria ja vaatimustaso:** Hukkaenergian uudelleenkäyttö – *laatuvaatimus*

### Mittarin lyhyt kuvaus
**Energy Reuse Factor (ERF)** on EN 50600-4-6 -standardin mukainen tunnusluku, joka kuvaa datakeskuksen käytössä syntyneen hukkalämmön uudelleenkäyttöastetta.

**Laskentakaava:**  

ERF = h / x

- **h** = uudelleenkäytetyn hukkalämmön määrä (kWh)  
- **x** = datakeskuksen kokonaisenergiankulutus (kWh)  

Arvo vaihtelee välillä 0–1. Mitä lähempänä arvo on 1, sitä suurempi osuus energiasta hyödynnetään uudelleen.

---

### Mitä mittari kertoo ja miten sitä käytetään?
- **Merkitys:** ERF kertoo, kuinka suuri osuus datakeskuksessa syntyvästä hukkalämmöstä otetaan talteen ja hyödynnetään muussa käytössä (esim. kaukolämmössä).  
- **Käyttö päätöksenteossa:** Vaikka ERF on hyödyllinen energiatehokkuuden indikaattori, tärkeintä on tietää, onko hukkalämmön hyötykäyttö toteutettu.  
- **Optimointimahdollisuudet:** Arvoa voi nostaa kehittämällä lämmön talteenottojärjestelmiä ja varmistamalla, että hukkalämpöä voidaan hyödyntää lähellä sijaitsevissa lämpöverkostoissa.

---

### Toteutuksen kustannus ja ympäristövaikutus
- **Kustannus:** Mittari voidaan lisätä osaksi ohjelmiston tai datakeskuksen toiminnallisia vaatimuksia. Toteutuskustannus on yleensä suhteellisen pieni, jos mittausjärjestelmä on jo olemassa.  
- **Ympäristövaikutus:** Suomessa datakeskusten hukkalämpö on yli 2 TWh vuodessa, mutta vain noin 10 % tästä on hyötykäytössä. Hyödyntämättä jäävä lämpö kuormittaa ilmastoa ja vesistöjä.

---

### Seuranta hankinnan aikana
Mittaria ei tarvitse seurata hankinnan aikana, jos datakeskusta ei vaihdeta tai jos hukkalämmön hyödyntämisestä ei luovuta.

---

### Edellytykset mittarin hyödyntämiselle
Mittari voidaan ottaa käyttöön, kun ohjelmisto toimii datakeskuksessa tai pilvipalvelussa, jossa voidaan mitata:
- datakeskuksen kokonaisenergiankulutus (kWh)  
- uudelleenkäytetyn energian määrä (kWh)

---

### Esimerkki
- **Kokonaisenergiankulutus (x):** 147 kWh  
- **Uudelleenkäytetty energia (h):** 79 kWh  
- **ERF = 0,54**

*Tulkinta:* Datakeskus hyödyntää uudelleen 54 % kokonaisenergiankulutuksestaan.

---

### Kriteeriin liittyvä mittaus ja viitearvot
- **Mittaus:** Kokonaisenergiankulutus (kWh) ja uudelleenkäytetyn energian määrä (kWh).  
- **Viitearvot:** Mitä lähempänä ERF-arvo on 1, sitä parempi. Virallisia referenssiviitearvoja ei ole määritelty.

---

### Kytkeytyvät mittarit
Muut EN 50600-4 -standardin avainlukuindikaattorit: **CER**, **CUE**, **PUE**, **REF**, **WUE**

