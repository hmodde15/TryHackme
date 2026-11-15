## Conclusion – Résumé de l'attaque

L'incident Tempest reconstitue une chaîne d'attaque complète sur le poste de
l'utilisateur *benimaru* (machine TEMPEST), depuis l'accès initial jusqu'à la
compromission totale en SYSTEM.

1. **Accès initial (Initial Access)**
   benimaru télécharge et ouvre un document Word piégé (`free_magicules.doc`)
   via Chrome. Word lance `msdt.exe` et exploite la faille **Follina
   (CVE-2022-30190)** pour exécuter une commande PowerShell encodée.

2. **Exécution / payload du document**
   Le PowerShell récupère `update.zip` depuis `phishteam[.]xyz`
   (167.71.199.191), l'extrait dans le dossier *Démarrage* (Startup) de
   l'utilisateur, puis supprime l'archive.

3. **Persistance au logon**
   À l'ouverture de session, l'implant du dossier Démarrage exécute un
   PowerShell masqué qui utilise `certutil` pour télécharger `first.exe` dans
   `C:\Users\Public\Downloads\` et le lancer (stage 2).

4. **Command & Control (C2)**
   `first.exe` (binaire Nim) communique avec **resolvecyber[.]xyz:80** en HTTP,
   commandes et résultats encodés en base64 (requêtes `GET /9ab62b5`, sortie
   dans le paramètre `q`). Un second canal passe par 167.71.199.191:8080.

5. **Reconnaissance et déplacement interne**
   L'attaquant énumère le système (`netstat -ano -p tcp` révèle WinRM sur le
   port 5985), télécharge **chisel** (`ch.exe`) pour monter un **proxy SOCKS
   inversé** vers son C2, récupère le mot de passe de benimaru
   (`infernotempest`) dans `automation.ps1`, puis s'authentifie via WinRM.

6. **Élévation de privilèges (Privilege Escalation)**
   En abusant du privilège **SeImpersonatePrivilege** avec **PrintSpoofer**
   (`spf.exe`), l'attaquant obtient les droits **SYSTEM** et exécute `final.exe`.

7. **Persistance et actions finales (Actions on Objective)**
   - Création de comptes locaux **Shion** et **Shuna** (Event ID 4720)
   - Ajout de *shion* au groupe Administrateurs (Event ID 4732)
   - Changement du mot de passe Administrateur
   - Création d'un service malveillant en démarrage automatique
     **TempestUpdate2** (`sc.exe`) pointant vers `C:\ProgramData\final.exe`

**Bilan :** une seule pièce jointe piégée a suffi à passer d'un simple clic
utilisateur à un contrôle total de la machine, avec persistance multiple
(dossier Démarrage, service auto-start, comptes admin créés) et un canal C2
masqué dans du trafic HTTP banal.
