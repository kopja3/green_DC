## EN 50600-4-2 (PUE) – Power Usage Effectiveness

**Kategoria ja vaatimustaso:** Energiatehokkuus – *laatuvaatimus*

### Mittarin lyhyt kuvaus
**Power Usage Effectiveness (PUE)** on EN 50600-4-2 -standardin mukainen tunnusluku, joka kuvaa datakeskuksen **kokonaisenergiankulutuksen** ja **IT-laitteiden** (palvelimet, tallennuslaitteet, verkkolaitteet) kulutuksen välistä suhdetta.  
Se on kansainvälisesti käytetyin energiatehokkuusmittari datakeskuksille.

**Laskentakaava:**  

PUE = Kokonaisenergiankulutus / IT-laitteiden energiankulutus


- **Kokonaisenergiankulutus:** sisältää kaiken datakeskuksen kuluttaman energian (IT-laitteet, jäähdytys, valaistus, UPS-häviöt jne.)  
- **IT-laitteiden energiankulutus:** sisältää vain tietojenkäsittelyyn, tallennukseen ja tiedonsiirtoon käytettävän energian  

Ihannetapauksessa **PUE = 1,0**, mikä tarkoittaisi, ettei mikään energia mene muuhun kuin IT-laitteiden käyttöön (käytännössä mahdotonta).

---

### Mitä mittari kertoo ja miten sitä käytetään?
- **Merkitys:** PUE kertoo, kuinka tehokkaasti datakeskus käyttää energiaa ydintoimintaansa (IT-prosessointiin) verrattuna tukitoimintoihin (esim. jäähdytys).  
- **Käyttö päätöksenteossa:** Matala PUE-arvo on tavoiteltava, koska se kertoo tehokkaasta energiankäytöstä. Arvo **1,2–1,5** on monissa nykyaikaisissa keskuksissa hyvä taso; yli **2,0** viittaa merkittävään tehostamispotentiaaliin.  
- **Optimointimahdollisuudet:** PUE-arvoa voidaan parantaa esimerkiksi optimoimalla jäähdytysratkaisut, hyödyntämällä hukkalämpöä ja vähentämällä tarpeetonta sähkönkulutusta tukijärjestelmissä.

---

### Toteutuksen kustannus ja ympäristövaikutus
- **Kustannus:** PUE:n mittaaminen vaatii energiankulutuksen seurantalaitteet sekä IT-laitteille että koko datakeskukselle. Useissa moderneissa keskuksissa järjestelmät ovat jo käytössä, jolloin kustannus voi olla vähäinen.  
- **Ympäristövaikutus:** Matala PUE vähentää sähkönkulutusta ja siten hiilijalanjälkeä. Vaikutus riippuu siitä, kuinka paljon tukijärjestelmien kulutusta saadaan pienennettyä.

---

### Seuranta hankinnan aikana
PUE-arvo voi vaihdella kuormituksen, sääolosuhteiden ja käyttötilanteiden mukaan.  
Siksi sitä kannattaa mitata säännöllisesti (esim. kuukausi- tai vuosikeskiarvona) ja verrata vertailuarvoihin.

---

### Edellytykset mittarin hyödyntämiselle
Datakeskuksen energiankulutus täytyy pystyä mittaamaan erikseen **IT-laitteiden** ja **koko keskuksen** osalta.  
Mittari soveltuu sekä omiin konesaleihin että pilvipalveluntarjoajien raportoituihin tietoihin.

---

### Esimerkki
- **Kokonaisenergiankulutus:** 1 200 kWh/vrk  
- **IT-laitteiden energiankulutus:** 1 000 kWh/vrk  
- **PUE = 1,20**  

*Tulkinta:* Tukijärjestelmät kuluttavat 20 % IT-laitteiden kulutuksen lisäksi. Tämä on tehokas taso moniin käyttötarkoituksiin.
