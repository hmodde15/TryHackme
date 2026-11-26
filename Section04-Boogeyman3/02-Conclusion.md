## Conclusion – Résumé de l'attaque (Boogeyman 3)

L'incident Boogeyman 3 est le dernier volet de la campagne du groupe **Boogeyman**
contre Quick Logistics LLC. Depuis une boîte mail compromise lors d'une étape
précédente, les attaquants ciblent cette fois le PDG, **Evan Hutchinson**. Ils partent
de son poste pour aller jusqu'à la **compromission complète du domaine Active
Directory** et au **déploiement d'un ransomware**. L'investigation repose sur
l'analyse des logs centralisés dans **Elastic (Kibana)** : Sysmon, PowerShell et
événements Windows, entre le 29 et le 30 août 2023.

1. **Accès initial (Initial Access) – Spear phishing**
   Evan reçoit un e-mail suspect envoyé depuis une boîte interne compromise. La pièce
   jointe est une **image ISO** qui contient un faux PDF,
   `ProjectFinancialSummary_Q3.pdf`, en réalité un fichier **HTA**. Evan l'ouvre et,
   comme « rien ne se passe », signale l'e-mail à l'équipe de sécurité. Mais la
   charge s'est déjà exécutée en arrière-plan.

2. **Exécution (Execution) – HTA → DLL (stage 2)**
   Le fichier HTA est exécuté par **`mshta.exe`**. Il copie le fichier **`review.dat`**
   depuis l'ISO montée (`D:\`) vers
   `C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat` avec `xcopy`, puis le lance
   avec **`rundll32.exe review.dat,DllRegisterServer`**.
   → `review.dat` est en réalité une **DLL malveillante** : l'extension `.dat` sert
   de **camouflage**.

3. **Persistance (Persistence) – Tâche planifiée**
   Une **tâche planifiée `Review`** est créée en **PowerShell** avec
   `Register-ScheduledTask`. Elle relance chaque jour à 06:00
   `rundll32.exe ...\review.dat,DllRegisterServer` sous le compte d'Evan.

4. **Command & Control (C2)**
   L'implant `review.dat` établit une connexion vers le C2 de l'attaquant
   (**`165.232.170.151:80`**). Ce canal donne à l'attaquant un shell PowerShell sur
   le poste du PDG.

5. **Élévation de privilèges (Privilege Escalation) – Contournement de l'UAC**
   L'attaquant exploite **`fodhelper.exe`**, un binaire Windows auto-élevé, pour
   **contourner l'UAC** et obtenir un shell avec des privilèges élevés, sans
   aucune invite visible pour l'utilisateur.

6. **Accès aux identifiants (Credential Access)**
   - L'attaquant télécharge **Mimikatz** depuis GitHub (`github.com/gentilkiwi/mimikatz`).
     Sysmon 22 (DNS) ne montre que le domaine `github.com` : l'URL complète se trouve
     dans la ligne de commande PowerShell.
   - Avec `sekurlsa::logonpasswords`, il extrait de la mémoire (LSASS) le **hash NTLM**
     du compte **`itadmin`**, puis l'utilise en **Pass-the-Hash**.
   - Il **énumère le partage réseau** `\\WKSTN-1327.quicklogistics.org\ITFiles` et lit
     le script **`IT_Automation.ps1`**, qui contient des **identifiants en clair**
     (compte `allan.smith`).

7. **Mouvement latéral (Lateral Movement)**
   Avec ces identifiants, l'attaquant rebondit sur la machine **`WKSTN-1327`** via
   **PowerShell Remoting / WinRM**. Le process parent `wsmprovhost.exe` en est la
   signature. Il y relance Mimikatz pour récupérer de nouveaux hashes, dont celui
   d'un compte à privilèges élevés.

8. **Compromission du domaine (Domain Compromise) – DCSync**
   Depuis ce nouvel accès, l'attaquant atteint le **contrôleur de domaine** et
   exécute une attaque **DCSync** (`lsadump::dcsync`). Il se fait passer pour un
   contrôleur de domaine et demande la réplication des hashes de mots de passe, dont
   celui du compte **`backupda`**.
   → À ce stade, **tout le domaine est compromis**.

9. **Impact – Ransomware**
   Enfin, l'attaquant télécharge un **ransomware** (`ransomboogey.exe`) depuis un
   serveur qu'il contrôle, dans le but de chiffrer les machines de l'entreprise.

**Bilan :** l'attaque part d'une simple pièce jointe ouverte par le PDG et va jusqu'à
la **prise de contrôle totale de l'Active Directory**. Elle illustre une chaîne
complète du **kill chain** : accès initial, persistance, élévation de privilèges, vol
d'identifiants, mouvement latéral, compromission du domaine et impact. Plusieurs
faiblesses ont été exploitées : un format de pièce jointe dangereux (ISO / HTA)
non bloqué, un utilisateur aux droits administrateur locaux, des **identifiants en
clair dans un script partagé** et la réutilisation de comptes privilégiés sur des
postes de travail. La réponse à incident impose d'isoler les machines touchées, de
réinitialiser **tous** les comptes du domaine, y compris **deux fois le compte
`krbtgt`**, de supprimer la tâche planifiée `Review`, de bloquer les IOCs (IP du C2,
domaines) et de bloquer les fichiers ISO / HTA en pièce jointe.

**Artefacts clés de l'investigation :** e-mail de phishing, image ISO
(`ProjectFinancialSummary_Q3.pdf` + `review.dat`), logs Sysmon (événements 1, 3, 11,
22), logs PowerShell (4104), événements de sécurité Windows, centralisés dans Elastic.

**Outils / techniques observés :** `mshta.exe`, `xcopy`, `rundll32.exe`,
`Register-ScheduledTask`, `fodhelper.exe` (UAC bypass), Mimikatz
(`sekurlsa::logonpasswords`, `sekurlsa::pth`, `lsadump::dcsync`), PowerShell Remoting
(WinRM).

**Requêtes KQL utiles :**

```
process.command_line : *review.dat*
process.name : "powershell.exe" and process.command_line : *Register-ScheduledTask*
process.command_line : *github*
process.command_line : *dcsync*
process.parent.name : "wsmprovhost.exe"
```
