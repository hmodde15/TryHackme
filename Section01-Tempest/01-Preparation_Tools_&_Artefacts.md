# Préparation des artefacts et outils d'investigation

Dans cette tâche, nous allons préparer les artefacts et présenter les outils nécessaires à l'investigation.

## Comparaison par hash

Avant de mener l'investigation, l'une des étapes les plus importantes consiste à comparer les artefacts par leur hash. C'est une pratique courante pour vérifier que les artefacts n'ont pas été modifiés.

Vous pouvez obtenir le hash de chaque artefact en lançant PowerShell depuis la barre des tâches et en exécutant les commandes suivantes :

```powershell
PS C:\Users\user> cd '.\Desktop\Incident Files\'
```

```powershell
PS C:\Users\user\Desktop\Incident Files> ls

    Directory: C:\Users\user\Desktop\Incident Files

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/21/2022   1:46 AM       17479060 capture.pcapng
-a----        6/21/2022   1:30 AM        3215360 sysmon.evtx
-a----        6/21/2022   1:29 AM        1118208 windows.evtx
```

```powershell
PS C:\Users\user\Desktop\Incident Files> Get-FileHash -Algorithm SHA256 .\capture.pcapng

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6       C:\Users\user\...
```

## Outils

Les outils de cette tâche servent à analyser les logs Sysmon, les journaux d'événements Windows et la capture réseau.

### Logs endpoint

Pour analyser les artefacts Windows (journaux d'événements Windows et logs Sysmon), on utilisera :

- EvtxECmd
- Timeline Explorer
- SysmonView
- Event Viewer (Observateur d'événements)

### Logs réseau

Pour analyser la capture de paquets fournie, on utilisera :

- Wireshark
- Brim

> **Note :** tous ces outils sont accessibles depuis la barre des tâches.

Wireshark, Brim et Event Viewer ont déjà été vus dans les rooms prérequises. Cette section ne présente donc que les nouveaux outils.

## EvtxECmd et Timeline Explorer

Eric Zimmerman a créé un ensemble d'outils forensiques pour analyser les artefacts Windows, appelé **EZTools** (Eric Zimmerman's Tools). Ici, on se concentre sur EvtxECmd et Timeline Explorer, qui servent surtout à parser et analyser les logs EVTX.

**EvtxECmd** est un outil en ligne de commande qui convertit les journaux d'événements Windows dans différents formats (CSV, JSON, XML, etc.). On peut l'utiliser avec **Timeline Explorer**, du même auteur. Timeline Explorer est un outil graphique qui permet de filtrer et de parcourir les données, pour faciliter le travail des analystes en réponse à incident face à des données brutes.

Pour parser les logs fournis, on convertit d'abord les EVTX en CSV avec EvtxECmd, puis on charge le CSV dans Timeline Explorer.

EvtxECmd étant un outil en ligne de commande, il n'a pas d'icône dans la barre des tâches. Ouvrez PowerShell depuis la barre des tâches, placez-vous dans le dossier de l'outil avec `cd C:\Tools\EvtxECmd`, puis lancez la commande ci-dessous.

> **Important :** gardez les guillemets simples autour des chemins, parce que le nom du dossier `Incident Files` contient un espace.

L'exemple parse `sysmon.evtx`. Pour parser `windows.evtx`, lancez :

```powershell
.\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\windows.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf windows.csv
```

Exemple avec `sysmon.evtx` :

```powershell
PS C:\Tools\EvtxECmd> .\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
EvtxECmd version 1.0.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/evtx

Command line: -f C:\Users\user\Desktop\Incident Files\sysmon.evtx --csv C:\Users\user\Desktop\Incident Files --csvf sysmon.csv

Warning: Administrator privileges not found!

CSV output will be saved to C:\Users\user\Desktop\Incident Files\sysmon.csv

Maps loaded: 383

Processing C:\Users\user\Desktop\Incident Files\sysmon.evtx...
Chunk count: 42, Iterating records...

Event log details
Flags: None
Chunk count: 42
Stored/Calculated CRC: EAFDE57A/EAFDE57A
Earliest timestamp: 1601-01-01 00:00:00.0000000
Latest timestamp:   2022-06-20 17:30:35.3630890
Total event log records found: 2,559

Records included: 2,559 Errors: 0 Events dropped: 0

Metrics (including dropped events)
Event ID        Count
1               238
2               2
3               92
5               3
8               3
11              1,024
12              186
13              869
15              6
22              136

Processed 1 file in 19.8850 seconds
```

### Charger le CSV dans Timeline Explorer

Pour **TimelineExplorer.exe**, chargez le CSV exporté : **File > Open**, puis choisissez `sysmon.csv` dans le dossier `C:\Users\user\Desktop\Incident Files`.

Une fois les logs chargés, vous pouvez parcourir chaque colonne et utiliser le champ de saisie en haut de la colonne pour filtrer les logs sur une chaîne précise.

Enfin, la fonction de recherche en haut à droite permet de trouver une chaîne qui peut apparaître dans n'importe quelle colonne.

## SysmonView

**SysmonView** est un outil graphique Windows qui permet de visualiser les logs Sysmon.

Avant de l'utiliser, il faut exporter le contenu du fichier de logs en XML depuis l'Observateur d'événements (Event Viewer). Un message vous prévient quand l'export est terminé.

### Utilisation

1. Allez dans **File > Import Sysmon Event Logs**, puis choisissez les fichiers XML générés avec l'Observateur d'événements.
2. Une fois les logs chargés, la barre latérale gauche contient une fonction de recherche qui permet de filtrer sur un processus précis.
3. Choisissez le chemin de l'image (image path) et le GUID de session pour afficher la vue cartographiée.

Cet outil permet de voir facilement les événements corrélés à un processus donné. Dans l'exemple de la room, la vue résume tous les événements Sysmon liés à `explorer.exe`.

---

### Question :

What is the SHA256 hash of the capture.pcapng file?

What is the SHA256 hash of the sysmon.evtx file?

What is the SHA256 hash of the windows.evtx file?




