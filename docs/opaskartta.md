# Vihreä datakeskus – oppaiden ristiinviittausmuistio

Tällä muistilapulla pidetään kirjaa siitä,
mitkä Perusoppaan ja Optimointioppaan luvut
syventävät Itseopiskelijan oppaan moduuleja.

## Taulukko 1 – Moduulit ja niitä syventävät luvut

| Moduuli (Itseopiskelijan opas) | Perusopas – luku/sivu(t), joka syventää taustaa | Optimointiopas – luku/sivu(t), joka syventää optimointia | Huomiot / mitä tässä kannattaa syventää |
|--------------------------------|-------------------------------------------------|----------------------------------------------------------|-----------------------------------------|
| Moduuli 1 – Datakeskuksen rakentamisen syyt ja sijaintipäätösten perusteet | Luku 1: Miksi datakeskus rakennetaan? sekä luku 2: Sijaintipäätöksiin vaikuttavat tekijät | Luku 2: Datakeskus tekoälyn näkökulmasta – mitattavat suureet eri osista | esim. syyt rakentamiselle, sijaintikriteerit, peruskäsitteet |
| Moduuli 2 – Vihreän datakeskuksen elementit ja periaatteet | Luku 3: Vihreän datakeskuksen elementit (energia, hukkalämpö, vesi, hiilineutraalius, kiertotalous, sertifioinnit) | Luku 2: Datakeskus tekoälyn näkökulmasta (mitattavat suureet) ja luku 4: Tekoälyn käyttötapaukset (jäähdytys, hukkalämpö, vesi, hiilineutraalius) | energianlähde, energiatehokkuus, hukkalämpö, vesi, hiilineutraalius |
| Moduuli 3 – Datakeskuksen elinkaaren vaiheet | Luku 4: Datakeskuksen elinkaari (esiselvitys–suunnittelu–rakentaminen–käyttö–modernisointi–purku) | Luku 5: Optimointi elinkaaren eri vaiheissa (mitä mitataan ja mitä AI voi optimoida missäkin vaiheessa) | suunnittelu–rakentaminen–käyttö–purku ja optimointikohdat |
| Moduuli 4 – Datakeskuksen toiminta vaiheittain | Luku 5: Datakeskuksen toiminta – sähköstä palveluksi (sähkönsyöttö, jäähdytys, palvelimet, verkko) | Luku 2: Mitattavat suureet ketjun eri vaiheista sekä luku 4: Case-esimerkit (jäähdytyksen optimointi, palvelinkuorman sijoittelu) | sähkö → palvelin → lämpö, tekninen perusta ja optimointi |
| Moduuli 5 – Energian kulutus ja uudelleenkäyttö | Luku 6: Energian kulutus datakeskuksessa ja hukkalämmön hyödyntäminen | Luku 3: Datan keruu kulutuksen seurantaan sekä luku 4: Energiankulutuksen ja PUE:n ennustaminen ja optimointi | PUE, kulutuksen vähentäminen, hukkalämmön hyödyntäminen |
| Moduuli 6 – EN 50600-4 -standardi ja mittarit | Luku 7: EN 50600-4 -mittarit – peruskuvaus (mitä kukin mittari kertoo) | Luku 3: Mittaridatan keruu ja yhdistäminen sekä luku 5: Mittareihin perustuva optimointiprosessi | mittareiden idea (perus) ja käytännön laskenta + seuranta |

## (Valinnainen) Tarkempi kartta Moduuli 2:lle

| Moduuli 2: Vihreän datakeskuksen elementit | Perusopas – luku/sivu | Optimointiopas – luku/sivu | Huomio |
|-------------------------------------------|------------------------|----------------------------|--------|
| Energianlähde                            | Luku 3, osio ”Energianlähde” | Luku 2: Mitattavat suureet energianlähteestä (uusiutuvat %, sopimukset) ja luku 4: Case energianlähteen optimoinnista | energialähteen valinta, uusiutuvan osuuden seuranta |
| Energiatehokkuus                         | Luku 3, osio ”Energiatehokkuus” | Luku 2: IT- ja jäähdytyskuorman mittarit sekä luku 4: Case jäähdytyksen ja IT-kuorman optimoinnista | lämpötilat, ilmavirrat, kuormanjako, konsolidointi |
| Hukkalämmön hyödyntäminen                | Luku 3, osio ”Hukkalämmön hyödyntäminen” | Luku 2: Lämmön mittarit ja luku 4: Case hukkalämmön ohjauksesta ja hyödyntämisestä | lämpöteho, lämpötilatasot, kytkentävaihtoehdot |
| Vedenkulutus                             | Luku 3, osio ”Vedenkulutus” | Luku 2: Vesijäähdytyksen ja vedenkulutuksen mittarit sekä luku 4: Case vedenkulutuksen vähentämisestä | WUE, jäähdytystapojen vertailu |
| Hiilineutraalius ja raportointi          | Luku 3, osio ”Hiilineutraalius ja raportointi” | Luku 3: Datan keruu päästölaskentaa varten ja luku 4: Case hiilineutraaliustavoitteiden ohjaamisesta mittarien avulla | Scope 1–3 perusajatus, datalähteet, raportointiketju |
| Kiertotalous ja materiaalien hallinta    | Luku 3, osio ”Kiertotalous ja materiaalien hallinta” | Luku 5: Elinkaaren aikainen optimointi ja laitekantaan liittyvä data | laitteiden elinkaari, päivitysrytmi, poisto- ja kierrätysdata |
| Sertifioinnit ja standardit              | Luku 3, osio ”Sertifioinnit ja standardit” | Luku 6: Sertifiointi, vaatimustenmukaisuus ja riskit (mitä mittareita ja dataa AI voi tuottaa sertifioinnin tueksi) | EN 50600, ISO 50001, miten AI auttaa todentamisessa |
