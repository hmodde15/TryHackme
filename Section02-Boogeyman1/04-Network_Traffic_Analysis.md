# Boogeyman 1 

D'après l'analyse des logs PowerShell, on a constaté l'impact complet de l'attaque :

* L'attaquant a pu lire et exfiltrer deux fichiers potentiellement sensibles.
* Les domaines et ports utilisés pour l'activité réseau ont été identifiés, y compris l'outil utilisé par l'attaquant pour l'exfiltration.

## Guide d'investigation

Enfin, on peut terminer l'investigation en comprenant le trafic réseau généré par l'attaque :

* Utilise les domaines et ports découverts dans la tâche précédente.
* Toutes les commandes exécutées par l'attaquant ainsi que toutes leurs sorties ont été enregistrées et stockées dans la capture réseau.
* Suis les flux (Follow Stream) des commandes notables identifiées dans les logs PowerShell.
* À partir des logs PowerShell, on peut récupérer le contenu des données exfiltrées en comprenant comment elles ont été encodées puis extraites.

### Question :

1 - Quel logiciel l'attaquant utilise-t-il pour héberger son serveur de fichiers/charges utiles présumé ?

on utilise le filtre wireshark : ip.addr == 167.71.211.113 && http

![Tryhackme](00-Images/domain1.png) 

Sur la photo :

GET /update → le stager récupère le stage 2
GET /sb.exe → 200 OK (application/x-msdos-program) → téléchargement d’un exécutable
GET /sq3.exe → binaire sqlite3.exe pour lire une base de données locale
Donc sur cette IP (167.71.211.113), le C2 ne fait que servir des fichiers. L’exfiltration part ailleurs.

réponse : python

2 - Quelle méthode HTTP est utilisée par le C2 pour transmettre le résultat des commandes exécutées par l'attaquant ?

On utilise le filtre : http.host contains bpakcaging.xyz

![Tryhackme](00-Images/post.png) 

rappel : 

| Méthode | Sert à | Où sont les données |
|---|---|---|
| GET | Récupérer / télécharger une ressource | Dans l'URL (query string) |
| POST | Envoyer des données au serveur | Dans le body |
| PUT | Créer / remplacer une ressource | Body |
| DELETE | Supprimer une ressource | — |
| HEAD | Comme GET mais réponse sans body (juste les headers) | — |
| OPTIONS | Demander les méthodes autorisées | — |

réponse : post 

3 - Quel est le protocole utilisé lors de l’opération d’exfiltration ?

L'outil utilisé est nslookup et on observe un gros trafic DNS dans la trame.

réponse : DNS

4 - Quel est le mot de passe du fichier exfiltré ?

On sais que l'outil utilisé est sq3.exe.

On utilise donc le filtre http contains sq3 :

![Tryhackme](00-Images/httpsq3.png) 

On regarde le paquet qui correspond à l'execution de l'outil puis ensuite on regarde celui d’âpres pour récupérer les infos transmise via la requete POST :

![Tryhackme](00-Images/get.png) 

![Tryhackme](00-Images/post1.png) 

On décode via cyberchef le traffic : 

![Tryhackme](00-Images/cybersq3.png) 

réponse : %p9^3!lL^Mz47E2GaT^y

Quel est le numéro de carte bancaire contenu dans le fichier exfiltré ?

On récupére le traffic DNS transmis à l'attaquant avec tshark avec la commande : tshark -r capture.pcapng -Y "dns && ip.dst == 167.71.211.113" -T fields -e dns.qry.name | awk '!seen[$0]++' > dns.txt

Puis je retire le domaine pour avoir un fichier propre : grep '\.bpakcaging\.xyz$' dns.txt | cut -d'.' -f1 | tr -d '\n' | xxd -r -p > dns.kdbx

![Tryhackme](00-Images/xxd.png) 

On ouvre ensuite la base keepass avec keepass2 dns.kdbx

On se connecte avec le mot de passe et on récupére le numéro de carte bancaire :

![Tryhackme](00-Images/basekeepass.png)

réponse : 4024007128269551








