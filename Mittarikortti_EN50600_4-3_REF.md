## EN 50600-4-3 (REF) – Renewable Energy Factor

**Kategoria ja vaatimustaso:** Uusiutuvan energian käyttö – *laatuvaatimus*

### Mittarin lyhyt kuvaus
**Renewable Energy Factor (REF)** on EN 50600-4-3 -standardin mukainen tunnusluku, joka kuvaa datakeskuksen **tuottaman ja hallinnoiman uusiutuvan energian** osuutta sen **kokonaisenergiankulutuksesta**.

**Laskentakaava:**  

REF = r / x

- **r** = datakeskuksen tuottaman ja hallinnoiman uusiutuvan energian määrä (kWh)  
- **x** = datakeskuksen kokonaisenergiankulutus (kWh)  

REF-arvo vaihtelee välillä 0–1. Mitä lähempänä arvo on 1, sitä suurempi osa energiasta on uusiutuvaa.

---

### Mitä mittari kertoo ja miten sitä käytetään?
- **Merkitys:** REF kertoo, kuinka suuri osuus datakeskuksen energiantuotannosta on uusiutuvaa. Tämä vaikuttaa suoraan hiilijalanjälkeen.  
- **Käyttö päätöksenteossa:** Korkea REF-arvo on tavoiteltava, sillä se tarkoittaa, että datakeskus on vähemmän riippuvainen fossiilisista energialähteistä.  
- **Optimointimahdollisuudet:** REF-arvoa voi parantaa lisäämällä omaa uusiutuvan energian tuotantoa (aurinko-, tuuli- tai vesivoima) tai hankkimalla uusiutuvaa energiaa luotettavista lähteistä.

---

### Toteutuksen kustannus ja ympäristövaikutus
- **Kustannus:** Mittari voidaan sisällyttää osaksi ohjelmiston tai datakeskuksen toiminnallisia vaatimuksia, joten toteutus on usein helppo ja edullinen.  
- **Ympäristövaikutus:** Käyttämällä uusiutuvaa energiaa datakeskus pienentää hiilijalanjälkeään samassa suhteessa. Kun energia on itse tuotettua, sen ympäristövaikutukset ovat varmimmin hallinnassa.

---

### Seuranta hankinnan aikana
REF-arvon toteutumista ei yleensä tarvitse seurata jatkuvasti hankinnan aikana, ellei datakeskuksen energiantuotannossa tapahdu muutoksia.

---

### Edellytykset mittarin hyödyntämiselle
Mittari voidaan ottaa käyttöön, kun järjestelmä toimii datakeskuksessa tai pilvipalvelussa, jossa energiantuotannon lähteet ja kokonaiskulutus ovat mitattavissa.

---

### Esimerkki
- **Tuotettu uusiutuva energia (r):** 99 kWh  
- **Kokonaisenergiankulutus (x):** 147 kWh  
- **REF = 0,67**

*Tulkinta:* Datakeskus tuottaa itse 67 % kuluttamastaan energiasta uusiutuvilla lähteillä.

---

### Kriteeriin liittyvä mittaus ja viitearvot
- **Mittaus:** Datakeskuksen uusiutuvan energian tuotanto (kWh) ja kokonaisenergiankulutus (kWh).  
- **Viitearvot:** Mitä lähempänä REF-arvo on 1, sitä parempi. Virallisia referenssiviitearvoja ei ole määritelty.
