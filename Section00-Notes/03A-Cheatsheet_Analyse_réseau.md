# Cheatsheet – Analyse réseau (Wireshark / tshark / HTTP)

Mémo personnel de commandes de base pour l'analyse de trafic en investigation SOC.

---

## 1. Filtres d'affichage Wireshark

> À taper dans la barre de filtre (fond vert = syntaxe valide). Ce sont des
> **filtres d'affichage**, différents des filtres de capture.

### Par adresse / hôte

| Filtre | Effet |
|---|---|
| `ip.addr == 10.0.0.5` | tout le trafic depuis OU vers cette IP |
| `ip.src == 10.0.0.5` | trafic dont la source est cette IP |
| `ip.dst == 10.0.0.5` | trafic dont la destination est cette IP |
| `ip.addr == 10.0.0.0/24` | tout un sous-réseau |

### Par protocole / port

| Filtre | Effet |
|---|---|
| `http` | uniquement le HTTP |
| `dns` | uniquement le DNS |
| `tcp` / `udp` | par protocole transport |
| `tcp.port == 443` | port TCP précis (source ou dest) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | paquets SYN (débuts de connexion) |

### Combiner les filtres

| Opérateur | Sens | Exemple |
|---|---|---|
| `&&` | ET | `ip.dst == 1.2.3.4 && http` |
| `\|\|` | OU | `http \|\| dns` |
| `!` ou `not` | NON | `!arp` |
| `contains` | contient une chaîne | `http.host contains "bpak"` |

### Spécial HTTP

| Filtre | Effet |
|---|---|
| `http.request` | toutes les requêtes (GET, POST…) |
| `http.response` | toutes les réponses |
| `http.request.method == "GET"` | uniquement les GET |
| `http.request.method == "POST"` | uniquement les POST (souvent l'exfiltration) |
| `http.request.uri contains "login"` | filtrer sur l'URL demandée |
| `http.host == "exemple.com"` | filtrer sur le domaine |

### Spécial DNS

| Filtre | Effet |
|---|---|
| `dns.qry.name contains "bpak"` | requêtes vers un domaine |
| `dns.flags.response == 0` | uniquement les requêtes (pas les réponses) |
| `dns.qry.type == 1` | requêtes de type A |

### Suivre un échange

- Clic droit sur un paquet → **Follow → TCP Stream / HTTP Stream**
- Affiche toute la conversation (requête + réponse) dans l'ordre
- Indispensable pour lire le contenu d'un POST ou la réponse d'un C2

---

## 2. Rappel HTTP – méthodes

Une requête = le client envoie / le serveur répond.

| Méthode | Sert à | Où sont les données |
|---|---|---|
| GET | Récupérer / télécharger une ressource | Dans l'URL (query string) |
| POST | Envoyer des données au serveur | Dans le body |
| PUT | Créer / remplacer une ressource | Body |
| DELETE | Supprimer une ressource | — |
| HEAD | Comme GET mais réponse sans body | — |
| OPTIONS | Demander les méthodes autorisées | — |

**Réflexe SOC :**
- GET vers un C2 → le malware **reçoit** (commande, payload, outil)
- POST vers un C2 → le malware **envoie** (résultat, fichier exfiltré)

### Codes de statut (réponse serveur)

| Code | Catégorie |
|---|---|
| 2xx | Succès (`200 OK`) |
| 3xx | Redirection (`301`, `302`) |
| 4xx | Erreur client (`403`, `404`) |
| 5xx | Erreur serveur (`500`) |

---

## 3. tshark (Wireshark en ligne de commande)

### Options de base

| Option | Rôle |
|---|---|
| `-r fichier.pcapng` | lire un fichier de capture |
| `-Y "filtre"` | appliquer un filtre d'affichage (même syntaxe que Wireshark) |
| `-T fields` | sortie en champs bruts (au lieu du résumé) |
| `-e champ` | choisir le champ à afficher (à combiner avec `-T fields`) |
| `-c N` | limiter à N paquets |
| `-q` | mode silencieux (utile avec les stats) |

### Exemples utiles

```bash
# Lire une capture et afficher le résumé
tshark -r capture.pcapng

# Filtrer le HTTP d'un hôte
tshark -r capture.pcapng -Y "http && ip.dst == 1.2.3.4"

# Extraire uniquement les noms de domaine DNS demandés
tshark -r capture.pcapng -Y "dns" -T fields -e dns.qry.name

# Extraire les URL HTTP demandées
tshark -r capture.pcapng -Y "http.request" -T fields -e http.host -e http.request.uri

# Afficher plusieurs champs d'un coup
tshark -r capture.pcapng -T fields -e ip.src -e ip.dst -e tcp.port
```

---

## 4. Traitement texte (combiné à tshark)

| Commande | Rôle |
|---|---|
| `sort -u` | trie ET supprime les doublons (⚠️ réordonne) |
| `awk '!seen[$0]++'` | supprime les doublons **en gardant l'ordre d'origine** |
| `cut -d'.' -f1` | garde le 1er champ découpé au `.` |
| `tr -d '\n'` | supprime les retours à la ligne (met tout sur une ligne) |
| `grep 'motif$'` | garde les lignes finissant par le motif (`$` = fin de ligne) |
| `grep -i` | insensible à la casse |

---

## 5. Décodage

| Encodage | Indice (jeu de caractères) | Décoder |
|---|---|---|
| Hexadécimal | uniquement `0-9` `A-F` | `xxd -r -p` ou `basenc --decode-hex` |
| Base64 | `A-Z a-z 0-9 + /`, souvent `=` | `base64 -d` |
| Base64 UTF-16 (PowerShell) | base64 avec octets null (`-EncodedCommand`) | `base64 -d \| iconv -f UTF-16LE -t UTF-8` |

### Identifier un fichier décodé

```bash
file fichier.bin        # donne le type réel (archive, kdbx, image…)
od -A x -t x1z f.bin | head   # voir les premiers octets (magic bytes)
```

---

## 6. Combo type : exfiltration DNS (vu sur Boogeyman 1)

Données volées, encodées en hex, exfiltrées dans des sous-domaines DNS.

```bash
# 1. Extraire les requêtes DNS vers le C2, dédupliquées en gardant l'ordre
tshark -r capture.pcapng -Y "dns && ip.dst == C2_IP" -T fields -e dns.qry.name \
  | awk '!seen[$0]++' > exfil.txt

# 2. Ne garder que l'hex (virer domaine + doublons résiduels), décoder, écrire le fichier
grep '\.domaine\.xyz$' exfil.txt | cut -d'.' -f1 | tr -d '\n' | xxd -r -p > fichier_vole.bin

# 3. Identifier le fichier reconstitué
file fichier_vole.bin
```

> Note : le mot de passe d'une archive/coffre reconstitué n'est PAS dans le fichier.
> Il a été tapé par l'attaquant → à chercher dans les logs (ex. `powershell.json`).
