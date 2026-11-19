# Volatility

Volatility est un outil gratuit de forensic mémoire développé et maintenu par la Volatility Foundation, couramment utilisé par les analystes malware et SOC au sein d'une équipe blue team, ou dans le cadre de leurs solutions de détection et de surveillance. Volatility est écrit en Python et se compose de plugins et de modules Python conçus comme une approche « plug-and-play » pour analyser les dumps mémoire.

Volatility est disponible pour Windows, Linux et Mac OS, et est écrit entièrement en Python.

Volatility est le framework le plus utilisé au monde pour extraire des artefacts numériques depuis des échantillons demémoire volatile (RAM). 
Les techniques d'extraction sont réalisées de manière totalement indépendante du système analysé, tout en offrant une visibilité sur
l'état d'exécution (runtime) du système. 

Volatility repose sur de multiples plugins qui travaillent ensemble pour obtenir
des informations depuis le dump mémoire. Pour commencer à analyser un dump, tu
dois d'abord identifier le **type d'image (image type)**.
Comme Volatility est totalement indépendant du système analysé, cela permet une
**segmentation complète** tout en donnant une **visibilité totale** sur l'état
d'exécution du système.

Au moment de la rédaction, il existe deux dépôts principaux pour Volatility : l'un
construit sur Python 2, l'autre sur Python 3. Pour cette room, nous recommandons
d'utiliser la version **Volatility 3**, basée sur Python 3 :
https://github.com/volatilityfoundation/volatility3

Note : en lisant des articles de blog sur Volatility, tu pourras croiser la syntaxe
de Volatility 2. 

L'extraction d'une image mémoire peut être effectuée de différentes manières, selon les besoins de votre investigation :

| Outil | Note |
|---|---|
| **FTK Imager** | suite forensic (AccessData) ; capture RAM + imagerie disque, interface graphique |
| **Redline** | outil d'investigation de FireEye/Mandiant ; collecte et analyse mémoire |
| **DumpIt.exe** | capture rapide de la RAM en un clic (très simple, portable) |
| **win32dd.exe / win64dd.exe** | acquisition mémoire en ligne de commande (versions 32 / 64 bits) |
| **Memoryze** | outil d'acquisition et d'analyse mémoire (Mandiant) |
| **FastDump** | outil de capture mémoire (HBGary) |

L'utilisation d'un outil d'extraction sur une machine physique peut prendre beaucoup de temps.

La plupart des outils mentionnés ci-dessus génèrent un fichier au format « .raw ». Il existe toutefois des exceptions, comme Redline, qui peut utiliser son propre agent et sa propre structure de session.

Quand la cible est une VM, son fichier mémoire est directement récupérable sur
l'hôte, selon l'hyperviseur utilisé.

| Hyperviseur | Extension | Note |
|---|---|---|
| **VMware** | `.vmem` | image mémoire de la VM |
| **Hyper-V** | `.bin` | image mémoire de la VM |
| **Parallels** | `.mem` | image mémoire de la VM |
| **VirtualBox** | `.sav` | ⚠️ image mémoire **partielle** uniquement |

---

Depuis le passage à Python 3, la structure des plugins de Volatility a beaucoup
changé. Dans les versions précédentes, tu devais identifier un **profil d'OS**
correspondant exactement au système d'exploitation et à la version de build de
l'hôte — ce qui pouvait être difficile à trouver, ou donner des faux positifs avec
certains plugins. Avec Volatility 3, les profils ont été supprimés, et Volatility
**identifie automatiquement** le système et la version du fichier mémoire.

La façon de nommer les plugins a aussi changé. Dans les anciennes versions, le nom
du plugin était simplement le nom du plugin, universel pour tous les systèmes et
profils. Désormais, avec Volatility 3, tu dois **spécifier le système
d'exploitation avant** le plugin à utiliser, par exemple `windows.info` vs
`linux.info`. En effet, il n'y a plus de profils pour distinguer les systèmes, car
chaque OS a des structures et un fonctionnement mémoire radicalement différents.
Voici les préfixes d'OS disponibles :

* `.windows`
* `.linux`
* `.mac`

---

## Profil d'image
Par défaut, Volatility est livré avec tous les profils Windows existants, de
Windows XP à Windows 10.

Les profils d'image peuvent être difficiles à déterminer si tu ne connais pas
exactement la version et le build de la machine dont tu as extrait le dump mémoire.
Dans certains cas, on te fournit un fichier mémoire sans aucun contexte, et c'est à
toi de déterminer par où commencer. Dans ce cas, Volatility te couvre avec le
plugin `imageinfo`. Ce plugin prend le dump mémoire fourni et lui attribue une
liste des meilleurs profils d'OS possibles. Les profils d'OS ont depuis été
abandonnés (deprecated) avec Volatility 3 : nous n'aurons donc à nous soucier
d'identifier le profil que si nous utilisons Volatility 2 — ce qui simplifie
grandement l'analyse des dumps mémoire.

Note : `imageinfo` n'est pas toujours correct et peut donner des résultats variés
selon le dump fourni ; à utiliser avec prudence, et teste plusieurs profils de la
liste proposée.

Si nous cherchons quand même à obtenir des informations sur ce que fait tourner
l'hôte à partir du dump mémoire, nous pouvons utiliser les trois plugins suivants :
`windows.info`, `linux.info`, `mac.info`. Ce plugin fournit des informations sur
l'hôte à partir du dump mémoire.

Syntaxe : `python3 vol.py -f <fichier> windows.info`

