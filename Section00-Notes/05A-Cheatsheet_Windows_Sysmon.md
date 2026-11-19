# Cheatsheet – Event IDs Windows & Sysmon (SOC)

Mémo des journaux d'événements les plus utiles en investigation.

---

## Où sont les logs Windows

- **Security** → authentification, comptes, privilèges (le plus important en SOC)
- **System** → services, drivers, démarrage
- **Application** → applications
- **PowerShell / Operational** → activité PowerShell
- **Sysmon/Operational** → journal Sysmon (si installé)

Outils : Event Viewer (GUI), `wevtutil` (CLI), `Get-WinEvent` (PowerShell).

---

## 1. Event IDs Windows – Security

### Authentification / sessions

| ID | Signification | Intérêt SOC |
|---|---|---|
| **4624** | Ouverture de session réussie | qui s'est connecté, d'où, comment (voir Logon Type) |
| **4625** | Échec d'ouverture de session | **brute force**, password spraying (beaucoup de 4625) |
| **4634 / 4647** | Fermeture de session | fin de session |
| **4648** | Connexion avec identifiants explicites (runas) | mouvement latéral, usage de creds volées |
| **4672** | Privilèges spéciaux attribués à la connexion | connexion **admin/SYSTEM** |

### Logon Types (dans le 4624) – à connaître

| Type | Sens |
|---|---|
| 2 | connexion **interactive** (clavier physique) |
| 3 | **réseau** (accès à un partage, SMB) |
| 4 | **batch** (tâche planifiée) |
| 5 | **service** |
| 7 | déverrouillage d'écran |
| 8 | NetworkCleartext (mot de passe en clair sur le réseau) |
| 9 | NewCredentials (runas /netonly) |
| 10 | **RemoteInteractive** (RDP) → à surveiller |
| 11 | identifiants mis en cache |

### Comptes et groupes

| ID | Signification |
|---|---|
| **4720** | Création d'un compte utilisateur |
| 4722 | Compte activé |
| 4723 / 4724 | Changement / réinitialisation de mot de passe |
| 4725 | Compte désactivé |
| 4726 | Compte supprimé |
| **4732** | Ajout d'un membre à un groupe local (ex. Administrateurs) |
| 4728 | Ajout d'un membre à un groupe global |
| 4738 | Compte modifié |
| **4740** | Compte **verrouillé** (lockout) |

### Kerberos (Active Directory)

| ID | Signification | Intérêt |
|---|---|---|
| 4768 | Demande de ticket TGT | connexion au domaine |
| 4769 | Demande de ticket de service | **Kerberoasting** si en masse |
| 4771 | Échec de pré-authentification Kerberos | **AS-REProasting** / brute force |

### Exécution / persistance / défense

| ID | Signification | Intérêt |
|---|---|---|
| **4688** | Création d'un processus | voir le process + sa ligne de commande (si activé) |
| 4689 | Fin d'un processus | — |
| **4697** | Installation d'un service | **persistance** |
| **4698** | Création d'une tâche planifiée | **persistance** |
| **1102** | **Journal d'audit effacé** | l'attaquant couvre ses traces → alerte forte |

### System log

| ID | Signification |
|---|---|
| **7045** | Nouveau service installé | persistance (ex. outil type PsExec) |
| 7034/7036 | Service crashé / changement d'état |

### PowerShell

| ID | Journal | Signification |
|---|---|---|
| **4104** | PowerShell/Operational | **Script Block Logging** → contenu des scripts exécutés (très utile) |
| 4103 | PowerShell/Operational | journalisation des pipelines/modules |
| 400 / 800 | Windows PowerShell | démarrage moteur / exécution pipeline |

---

## 2. Event IDs Sysmon (les plus importants)

Sysmon (System Monitor) est un outil Sysinternals qui enrichit énormément la
télémétrie. Journal : **Microsoft-Windows-Sysmon/Operational**.

| ID | Événement | Intérêt SOC |
|---|---|---|
| **1** | **Création de processus** | le plus utile : commande complète, hash, parent → filiation d'attaque |
| 2 | Changement de date de création d'un fichier | **timestomping** (anti-forensic) |
| **3** | **Connexion réseau** | process ↔ IP/port → détection C2 |
| 4 | Changement d'état de Sysmon | Sysmon arrêté/démarré (évasion ?) |
| **5** | Fin de processus | corréler avec l'ID 1 |
| 6 | Chargement d'un driver | drivers malveillants / rootkits |
| **7** | Chargement d'une image (DLL) | DLL injectée / **DLL sideloading** |
| **8** | **CreateRemoteThread** | **injection de code** dans un autre process |
| 9 | RawAccessRead | lecture disque brute (exfil / contournement) |
| **10** | **ProcessAccess** | accès à la mémoire d'un process → **accès à lsass.exe = credential dumping** |
| **11** | **Création de fichier** | dépôt de payload, outils déposés |
| 12 / 13 / 14 | Événements de **registre** (clé créée, valeur modifiée) | persistance (Run keys…) |
| 15 | Création de flux de fichier (ADS) | **Alternate Data Streams** (cacher du code) |
| 17 / 18 | Pipe nommé créé / connecté | C2, outils type Cobalt Strike |
| 19 / 20 / 21 | Événements **WMI** | persistance / exécution via WMI |
| **22** | **Requête DNS** | résolution de domaines → détection C2 / exfil DNS |
| 23 / 26 | Suppression de fichier | effacement de preuves |
| 25 | Process tampering | **process hollowing / herpaderping** |

---

## Les ID à retenir en priorité (débutant)

- **4624 / 4625** → connexions réussies / échouées (+ Logon Type)
- **4688** + **Sysmon 1** → création de processus (la commande exacte)
- **Sysmon 3** / **Sysmon 22** → réseau et DNS (C2)
- **Sysmon 10** → accès à lsass (vol d'identifiants)
- **4720 / 4732 / 7045 / 4698** → création de compte, ajout admin, service, tâche planifiée (persistance)
- **1102** → effacement des logs (couverture de traces)

---

## Commandes utiles

```powershell
# Lire un journal avec PowerShell
Get-WinEvent -LogName Security -MaxEvents 50

# Filtrer sur un Event ID
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}

# Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50
```

```cmd
:: avec wevtutil
wevtutil qe Security /c:20 /f:text /q:"*[System[(EventID=4624)]]"
```
