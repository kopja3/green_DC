# Vihreä datakeskus – oppaiden ristiinviittausmuistio

Tällä muistilapulla pidetään kirjaa siitä,
mitkä Perusoppaan ja Optimointioppaan luvut
syventävät Itseopiskelijan oppaan moduuleja.

Optimointiopas on fokusoitu **käytön aikaiseen optimointiin**, jossa
datakeskuksesta kerätään mittausdataa, ja data-analytiikkaa sekä
syväoppimista hyödynnetään mm. sähkönkulutuksen ja CO₂-päästöjen
pienentämiseen, palvelinkuorman ja jäähdytyksen yhteentoimivuuden
optimointiin, hukkalämmön älykkääseen hyödyntämiseen sekä käytön ja
operoinnin jatkuvaan parantamiseen.

---

## Perusopas – luonnos sisällysluetteloksi

1. **Johdanto vihreään datakeskukseen**  
2. **Miksi datakeskus rakennetaan ja miten sijainti valitaan**  
3. **Vihreän datakeskuksen elementit ja periaatteet**  
4. **Datakeskuksen elinkaaren vaiheet**  
5. **Datakeskuksen toiminta: sähköstä palveluksi ja takaisin lämmöksi**  
6. **Energian kulutus ja hukkalämmön hyödyntäminen**  
7. **EN 50600-4 -mittarit ja muut keskeiset tunnusluvut**

## Optimointiopas – luonnos sisällysluetteloksi

1. **Johdanto data- ja tekoälyohjattuun optimointiin**  
2. **Datakeskus tekoälyn näkökulmasta: mittauspisteet ja mitattavat suureet**  
3. **Datan keruu, yhdistäminen ja perusanalytiikka**  
4. **Syväoppimisen käyttötapaukset: kulutus, jäähdytys, kuorma ja hukkalämpö**  
5. **Ohjausstrategiat: miten mallit kytketään konesalin ohjaukseen**  
6. **Jatkuva käytön aikainen optimointi, operointi ja riskienhallinta**

> Huom: Optimointioppaan luku 1 tukee kaikkia moduuleja, joten se
> mainitaan useilla riveillä.

---

## Taulukko 1 – Moduulit ja niitä syventävät luvut

| Moduuli (Itseopiskelijan opas) | Perusopas – luku/sivu(t), joka syventää taustaa | Optimointiopas – luku/sivu(t), joka syventää optimointia | Huomiot / mitä tässä kannattaa syventää |
|--------------------------------|-------------------------------------------------|----------------------------------------------------------|-----------------------------------------|
| **Moduuli 1 – Datakeskuksen rakentamisen syyt ja sijaintipäätösten perusteet** | Luku 1: Johdanto vihreään datakeskukseen; luku 2: Miksi datakeskus rakennetaan ja miten sijainti valitaan | Luku 1: Johdanto data- ja tekoälyohjattuun optimointiin (tavoitteet ja periaatteet) | syyt rakentamiselle, sijaintikriteerit, peruskäsitteet, miksi optimointia tarvitaan |
| **Moduuli 2 – Vihreän datakeskuksen elementit ja periaatteet** | Luku 3: Vihreän datakeskuksen elementit ja periaatteet | Luku 1: Johdanto (optimoinnin yleinen tavoite); luku 2: Datakeskus tekoälyn näkökulmasta (mittauspisteet); luku 4: Syväoppimisen käyttötapaukset (jäähdytys, kuorma, hukkalämpö, vesi, hiilineutraalius) | energianlähde, energiatehokkuus, hukkalämpö, vesi, hiilineutraalius, kiertotalous, sertifioinnit |
| **Moduuli 3 – Datakeskuksen elinkaaren vaiheet** | Luku 4: Datakeskuksen elinkaaren vaiheet | Luku 1: Johdanto (optimointi osana elinkaarta); luku 6: Jatkuva käytön aikainen optimointi, operointi ja riskienhallinta | suunnittelu–rakentaminen–käyttö–purku; mihin vaiheeseen AI-pohjainen optimointi erityisesti kytkeytyy (käyttö ja operointi) |
| **Moduuli 4 – Datakeskuksen toiminta vaiheittain** | Luku 5: Datakeskuksen toiminta: sähköstä palveluksi ja takaisin lämmöksi | Luku 2: Mittauspisteet sähkönsyötöstä, jäähdytyksestä ja palvelinkuormasta; luku 4: Syväoppimisen käyttötapaukset (kuorman ja jäähdytyksen yhteispeli); luku 5: Ohjausstrategiat (miten mallit vaikuttavat asetuksiin) | sähkö → palvelin → lämpö, tekninen perusta ja optimointikohdat (jäähdytys, kuorma, hukkalämpö) |
| **Moduuli 5 – Energian kulutus ja uudelleenkäyttö** | Luku 6: Energian kulutus ja hukkalämmön hyödyntäminen | Luku 1: Johdanto (tavoitteena CO₂- ja energiankulutuksen pienentäminen); luku 3: Datan keruu ja perusanalytiikka (kulutus, PUE, hukkalämpö); luku 4: Syväoppimisen käyttötapaukset (kulutuksen ennustaminen, PUE-optimointi, hukkalämmön ohjaus); luku 5: Ohjausstrategiat | PUE, kokonaiskulutus, kulutuksen vähentäminen, hukkalämmön älykäs hyödyntäminen |
| **Moduuli 6 – EN 50600-4 -standardi ja mittarit** | Luku 7: EN 50600-4 -mittarit ja muut keskeiset tunnusluvut | Luku 1: Johdanto (mittareiden rooli optimoinnissa); luku 3: Mittaridatan keruu ja yhdistäminen; luku 6: Jatkuva käytön aikainen optimointi (mittareihin perustuva seuranta ja päätöksenteko) | mittareiden idea (perus) ja käytännön käyttö: mihin mittareita syötetään ja miten AI hyödyntää niitä |

---

## (Valinnainen) Tarkempi kartta Moduuli 2:lle

| Moduuli 2: Vihreän datakeskuksen elementit | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|-------------------------------------------|------------------------|----------------------------|--------|
| Energianlähde                            | Luku 3, osio ”Energianlähde” | Luku 2: Mittauspisteet energianlähteeseen liittyen (esim. uusiutuvan energian osuus, sopimustiedot); luku 4: Case energianlähteen ja CO₂-intensiteetin optimoinnista | energialähteen valinta, uusiutuvan osuuden seuranta ja vaikutus CO₂:een |
| Energiatehokkuus                         | Luku 3, osio ”Energiatehokkuus” | Luku 2: IT- ja jäähdytyskuorman mittarit; luku 4: Case jäähdytyksen ja palvelinkuorman optimoinnista; luku 5: Ohjausstrategiat (asetukset, ohjauslogiikka) | lämpötilat, ilmavirrat, kuormanjako, konsolidointi, vaikutus PUE:hen |
| Hukkalämmön hyödyntäminen                | Luku 3, osio ”Hukkalämmön hyödyntäminen” | Luku 2: Lämmön mittarit (teho, lämpötilatasot); luku 4: Case hukkalämmön ohjauksesta (milloin ja minne lämpö ohjataan); luku 5: Ohjausstrategiat | lämpöteho, lämpötilatasot, kytkentävaihtoehdot, kysynnän mukaan ohjaaminen |
| Vedenkulutus                             | Luku 3, osio ”Vedenkulutus” | Luku 2: Vesijäähdytyksen ja vedenkulutuksen mittarit; luku 4: Case vedenkulutuksen vähentämisestä ilman riskien kasvua | WUE, jäähdytystapojen vertailu, vedenkulutuksen ja energiankulutuksen kompromissi |
| Hiilineutraalius ja raportointi          | Luku 3, osio ”Hiilineutraalius ja raportointi” | Luku 3: Datan keruu päästölaskentaa varten (CO₂-intensiteetti, kulutus); luku 4: Case hiilineutraaliustavoitteiden seuraamisesta mallien avulla; luku 6: Mittareiden ja tavoitteiden jatkuva seuranta | Scope 1–3 perusajatus, datalähteet, raportointiketju ja AI:n rooli trendien tunnistamisessa |
| Kiertotalous ja materiaalien hallinta    | Luku 3, osio ”Kiertotalous ja materiaalien hallinta” | Luku 6: Jatkuva optimointi ja laitekannan elinkaaren seuranta (esim. käyttöaste, ikä, energiatehokkuus) | laitteiden elinkaari, päivitysrytmi, poisto- ja kierrätysdata, energiatehokkuus vs. uusiminen |
| Sertifioinnit ja standardit              | Luku 3, osio ”Sertifioinnit ja standardit” | Luku 6: Jatkuva optimointi ja vaatimustenmukaisuus (mitä dataa AI ja mittarit voivat tuottaa sertifioinnin tueksi) | EN 50600, ISO 50001 jne., miten mittarointi ja AI helpottavat auditointeja |
