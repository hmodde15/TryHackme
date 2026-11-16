## Boogeyman

Dans cette room, tu vas devoir analyser les Tactiques, Techniques et Procédures (TTP) exécutées par un groupe malveillant, depuis l'obtention de l'accès initial jusqu'à la réalisation de son objectif.

### Prérequis

Cette room peut nécessiter l'ensemble des connaissances acquises dans le parcours SOC L1. Il est recommandé de parcourir les rooms suivantes avant de tenter ce challenge :

* [Phishing Analysis Fundamentals](https://tryhackme.com/room/phishingemails1tryoe)
* [Phishing Analysis Tools](https://tryhackme.com/room/phishingemails3tryoe)
* [Windows Event Logs](https://tryhackme.com/room/windowseventlogs)
* [Wireshark: Traffic Analysis](https://tryhackme.com/room/wiresharktrafficanalysis)
* [Tshark: The Basics](https://tryhackme.com/r/room/tsharkthebasics)

### Plateforme d'investigation

Avant de commencer, déploie la machine jointe en cliquant sur le bouton **Start Lab Machine** en haut à droite de la tâche. L'initialisation des services peut prendre de 3 à 5 minutes.

La machine démarre en vue partagée (split-screen). Si la VM n'est pas visible, utilise le bouton bleu **Show Split View** en haut à droite de la page.

### Artefacts

Pour mener l'investigation, les artefacts suivants te sont fournis :

* Copie de l'e-mail de phishing (`dump.eml`)
* Logs PowerShell du poste de travail de Julianne (`powershell.json`)
* Capture réseau du même poste (`capture.pcapng`)

> Note : le fichier `powershell.json` contient les logs PowerShell au format JSON, extraits du fichier `.evtx` d'origine via l'outil [evtx2json](https://github.com/Silv3rHorn/evtx2json).

Ces fichiers se trouvent dans le répertoire `/home/ubuntu/Desktop/artefacts`.

### Outils

La VM fournie contient les outils suivants :

* **Thunderbird** — client e-mail libre et multiplateforme.
* [**LNKParse3**](https://github.com/Matmaus/LnkParse3) — package Python pour l'analyse forensique de fichiers binaires avec l'extension LNK.
* **Wireshark** — analyseur de paquets en interface graphique.
* **Tshark** — version en ligne de commande de Wireshark.
* **jq** — processeur JSON léger et flexible en ligne de commande.

Pour parser et analyser efficacement les artefacts fournis, tu peux aussi utiliser les outils en ligne de commande intégrés :

* `grep`
* `sed`
* `awk`
* `base64`

Maintenant, partons à la chasse au Boogeyman !
