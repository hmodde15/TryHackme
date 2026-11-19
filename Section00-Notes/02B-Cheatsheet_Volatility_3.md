# Cheatsheet – Volatility 3 (forensic mémoire)

Mémo des plugins et commandes vus, pour l'analyse de dumps RAM en SOC.

---

## Syntaxe de base

```bash
vol -f <dump> <plugin> [options]
# ou, depuis les sources :
python3 vol.py -f <dump> <plugin> [options]
```

- `-f <dump>` → le fichier mémoire à analyser
- `-o <dossier>` → dossier de sortie pour les fichiers extraits (doit être inscriptible, ex. `/home/user`)
- plugin préfixé par l'OS : `windows.` / `linux.` / `mac.`

> **v2 → v3 :** plus de `--profile` (détection auto), et le plugin se préfixe
> désormais par l'OS (`pslist` → `windows.pslist`).

---

## 1. Cadrer le système

| Commande | Ce qu'elle fait |
|---|---|
| `windows.info` | infos sur l'hôte : OS, version/build, architecture. **Premier réflexe** sur un dump inconnu |

```bash
vol -f dump.raw windows.info
```

---

## 2. Processus

| Plugin | Ce qu'il fait | Particularité |
|---|---|---|
| `windows.pslist` | liste les processus (comme Task Manager) depuis la liste chaînée | inclut les process terminés + heure de fin |
| `windows.psscan` | retrouve les processus en scannant les structures `_EPROCESS` | voit les process **cachés/unlinked** (rootkits), mais peut faire des faux positifs |
| `windows.pstree` | liste les processus en **arbre** parent → enfant | idéal pour repérer une filiation anormale |

```bash
vol -f dump.raw windows.pstree
```

> **Réflexe clé :** comparer `pslist` et `psscan`. Un process présent dans
> `psscan` mais **absent** de `pslist` = tentative de dissimulation.

---

## 3. Réseau

| Plugin | Ce qu'il fait |
|---|---|
| `windows.netstat` | tente d'identifier les connexions réseau en mémoire |
| `windows.netscan` | scanne les structures réseau (connexions, ports) |

```bash
vol -f dump.raw windows.netscan
```

> `netstat` peut être **instable** sur les vieux builds Windows. En secours :
> extraire un PCAP du dump avec `bulk_extractor`.

---

## 4. DLL et fichiers

| Plugin | Ce qu'il fait |
|---|---|
| `windows.dlllist` | liste les **DLL chargées par un processus** (révèle ses capacités : réseau, crypto…) |
| `windows.filescan` | liste **tous les fichiers** présents en mémoire, avec leur chemin complet |

```bash
# DLL d'un process précis
vol -f dump.raw windows.dlllist --pid 740

# tous les fichiers, filtrés sur le dossier du malware
vol -f dump.raw windows.filescan | grep -i "<chemin_du_malware>"
```

> `dlllist` = DLL **d'un process** | `filescan` = **tous les fichiers** du système.

---

## 5. Détection / hunting

| Plugin | Ce qu'il fait |
|---|---|
| `windows.malfind` | détecte l'**injection de code** : zones mémoire exécutables (RWE/RX) sans fichier sur disque (fileless). Un en-tête `MZ` = exécutable injecté |
| `windows.yarascan` | compare la mémoire à des **règles YARA** (chaînes, motifs, signatures) |
| `windows.ssdt` | cherche le **SSDT hooking** (rootkit qui détourne la table des fonctions système) |
| `windows.modules` | liste les **modules noyau (drivers) chargés** ; peut manquer un driver caché/inactif |
| `windows.driverscan` | scanne les drivers présents, y compris ceux que `modules` a ratés |

```bash
vol -f dump.raw windows.malfind
```

> Les plugins avancés (`ssdt`, `modules`, `driverscan`) crachent beaucoup de
> lignes : à lancer **après** avoir une piste, pour confirmer/approfondir.

---

## 6. Extraire et fouiller la mémoire d'un process

Combo très utilisé : **dumper → strings → grep**.

```bash
# 1. extraire la mémoire du process suspect
vol -f dump.raw -o /home/user windows.memmap.Memmap --pid 1640 --dump
#    → génère pid.1640.dmp

# 2. sortir le texte lisible + filtrer sur un IOC
strings pid.1640.dmp | grep -i "user-agent"
```

Idées de `grep` (voir la fiche IOC dédiée) : `http`, IP, `.exe`, `powershell`,
`HKLM...Run`, `base64`, `bitcoin`, `mutex`…

```bash
# combiner plusieurs termes (| = OU)
strings pid.1640.dmp | grep -iE "http|\.exe|powershell"

# contexte autour de la ligne
strings pid.1640.dmp | grep -i "user-agent" -A 3 -B 3
```

---

## La démarche type d'une investigation

1. `windows.info` → quel système ?
2. `windows.pstree` → quel process anormal (nom, parent, chemin bizarre) ?
3. `windows.netscan` → vers quelle IP/domaine ça communique ?
4. comparer `pslist` / `psscan` → quelque chose se cache ?
5. `windows.dlllist --pid <PID>` → que sait faire le process (réseau ? crypto ?) ?
6. `windows.memmap --dump --pid <PID>` + `strings | grep` → extraire les IOC
7. `windows.filescan | grep` → quels fichiers le malware a déposés
8. `malfind` / `ssdt` / `modules` → confirmer injection / rootkit sur une piste

> Rappel forensic : on travaille sur une **copie figée** de la RAM, indépendante
> du système analysé → aucune preuve altérée, le malware ne peut pas se défendre.
