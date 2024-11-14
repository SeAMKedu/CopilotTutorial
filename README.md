# GitHub Copilot alkeet

## Yleistä GitHub Copilotista

GitHub Copilot on tekoälyyn pohjautuva ohjelmointityökalu, joka osaa tehdä ja täydentää ohjelmakoodia. Copilotille kuvataan ohjelmointitehtävä luonnollisella kielellä ja se tuottaa ratkaisun annettuun tehtävään valitulla ohjelmointikielellä. Haluttu uusi ohjelman toiminto voidaan kuvata esimerkiksi syöteikkunassa tai kuvaus voidaan kirjoittaa ohjelmakoodin kommentteihin. Copilot osaa myös ehdottaa seuraavia koodirivejä samalla, kun ohjelmoija kirjoittaa ohjelmakoodia. Tekoälyn avulla tuotetut koodin täydennykset auttavat ohjelmistokehittäjää etenkin vaikeasti muistettavien yksityiskohtien ohjelmoinnissa, ja ohjelmistokehittäjä voi keskittyä haastavampiin ohjelmistotehtäviin. Copilot toimii muun muassa Visual Studio Code (VS Code) -kehitystyökalussa.

Copilotia markkinoidaan tekoälypohjaisena pariohjelmoijana, jolta voi kysyä ohjeita ohjelmointityön aikana. Sitä voi pyytää selittämään annettua ohjelmakoodia tai virheilmoituksia. Virhetilanteissa se selittää ongelman ja antaa korjausehdotuksen. Copilot on myös hyödyllinen yksikkötestien laatimisessa. Työkalu osaa generoida suurempia koodikokonaisuuksia, jotka jakaantuvat useisiin ohjelmistomoduuleihin. Copilot toimii parhaiten, kun sille on annettu tietoa kehitettävän ohjelman kontekstista. Käytännössä tämä tarkoittaa sitä, että Copilotille kerrotaan, mitä ohjelmakoodia sen tulee huomioida koodiehdotuksia varten.

Useimmat ohjelmistokehittäjät käyttää nykyään GitHub Copilotia tai vastaavaa tekoälypohjaista ohjelmointityökalua. Ohjelmointityössä täytyy jatkuvasti hakea tietoa esimerkiksi ohjelmistokirjastojen ja rajapintojen käytöstä. Ohjelmistokehittäjät käyttävät myös useita ohjelmointikieliä ja sovelluskehyksiä, ja näihin liittyvien yksityiskohtien muistaminen ei ole mielekästä eikä edes mahdollista. Tekoälypohjaiset koodiavustajat nopeuttavat usein tiedonhankintaa web-sivujen selaamiseen verrattuna.

Toisaalta monet ovat huolissaan tekoälypohjaisten työkalujen vaikutuksesta ohjelmistojen laatuun. Kielimallien ongelma ohjelmistokehityksessä on, että niiden on vaikea ”hahmottaa” suuria useisiin tiedostoihin jakautuneita ohjelmistoprojekteja. Copilot ei selviydy vielä kovin hyvin tilanteesta, jossa uuden toiminnon lisääminen ohjelmaan vaatii muutoksia useisiin tiedostoihin. Myös ohjelmistokoodin uudelleenkäytössä on puutteita, koska kielimallit eivät osaa nykyisellään yleistää koodia. Tutkimuksissa on havaittu, että ohjelmakoodin uudelleenkäyttö on vähentynyt AI-työkalujen yleistyttyä. 

Kielimallit tuottavat varsin hyviä vastauksia melkein mihin vain tyypillisiin koulutehtäviin, joita esiintyy esimerkiksi lukioissa ja korkeakoulujen perusopinnoissa. Ohjelmoinnissa tilanne on sama kuin muissa aineissa. ChatGPT ja Copilot osaavat ratkaista suurimman osan ohjelmoinnin peruskurssien tehtävistä pelkän tehtävänannon perusteella. 

 Monet ohjelmoinnin opettajat ovat sitä mieltä, että opiskelijan ei kannattaisi käyttää tekoälyä ohjelmoinnin peruskurssien opiskelussa. Esimerkiksi Helsingin yliopiston suositussa Full Stack open -opiskelumateriaalissa annetaan suositus, että opiskelija kytkee Copilotin pois päältä ja turvautuu siihen ainoastaan silloin, kun muu ei auta. Tekoälyn olemassaoloa ei voi kuitenkaan piilottaa edes ohjelmoinnin perusteiden opiskelijoilta. Alkeisopinnoissakin tekoälystä voi olla opiskelijalle hyötyä esimerkiksi ohjelmakoodin selittäjänä. Kun ohjelmoinnin perustaidot ovat hallussa, tekoälypohjaisten koodiavustinten tehokasta käyttöä on myös syytä opiskella. Ohjelmoijan on osattava tuottaa itse algoritmeja, vaikka ne saakin generoitua helposti tekoälyn avulla. Ilman kunnollista ohjelmointiosaamista suunnittelija ei pysty arvioimaan tekoälyn tuottaman koodin oikeellisuutta ja tarkoituksenmukaisuutta.

## Sisältö

Tässä oppaassa kerrotaan, miten GitHub Copilotia käytetään Visual Studio Codessa. Esimerkeissä käytetään Python- ja Java-ohjelmointikieliä. Oppaassa kerrotaan seuraavista Copilotin käyttöön liittyvistä asioista:
- Miten koodiehdotukset saa editoriin ja miten niitä hyödynnetään
- Miten käytetään chat-keskusteluja koodin refaktorointiin
- Miten korjataan virheitä

## Inline chat

Tehdään GitHub Copilotin avulla ohjelma, joka lukee tiedostosta dataa Suomen suurimmista kaupungeista. Ohjelma järjestää kaupungit eri parametrien mukaan.

Tietoja kaupungeista voitaisiin hakea esimerkiksi Tilastokeskuksen sivuilta. Tehdään tekstitiedosto kaupungeista nyt kuitenkin tekoälyn avulla.

Tee VS Codella tiedosto cities.txt.

![](images/firstinlinechat.png)

