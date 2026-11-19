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

---

L'extraction d'une image mémoire peut être effectuée de différentes manières, selon les besoins de votre investigation. 

Les outils : 

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

Dans le cas de machines virtuelles, l'obtention d'une image mémoire peut être réalisée simplement en récupérant le fichier de mémoire virtuelle sur le disque de la machine hôte. Le format de ce fichier varie en fonction de l'hyperviseur utilisé ; voici quelques exemples de fichiers de mémoire virtuelle que vous pourriez rencontrer :

VMWare - .vmem
Hyper-V - .bin
Parallels - .mem
VirtualBox - .sav (il s'agit ici d'une image mémoire partielle)
