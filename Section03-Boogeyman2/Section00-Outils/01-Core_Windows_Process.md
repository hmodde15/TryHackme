# Core Windows Processes – Notes de révision

## Partie 1 – Task Manager

Utilitaire graphique natif de Windows pour voir les processus en cours et leur
consommation (CPU, mémoire). Clic droit sur la barre des tâches → Task Manager,
puis **More details** pour tout afficher.

### Colonnes utiles à ajouter (clic droit sur l'en-tête)

Les colonnes par défaut sont pauvres. Pour l'analyse, ajoute :

| Colonne | Pourquoi c'est utile |
|---|---|
| **PID** | identifiant unique attribué à chaque processus au démarrage |
| **Image path name** | le **chemin** de l'exécutable → repère un binaire au mauvais endroit |
| **Command line** | la commande complète de lancement → révèle args, URL, scripts |
| Publisher | éditeur/auteur du programme |

> Onglet **Details** : trie par PID croissant pour retrouver les processus système.
> `Image path name` + `Command line` suffisent souvent à repérer un **outlier**
> (ex. un `svchost.exe` lancé depuis un chemin anormal).

### La grosse limite de Task Manager

Task Manager **n'affiche PAS la relation parent-enfant** entre processus.
Or le parent est un critère clé pour détecter un intrus.

Exemple : un `svchost.exe` a le PID 384, alors que son parent légitime
`services.exe` a le PID 632. Un PID enfant « avant » son parent n'a pas de sens →
en réalité Task Manager masque juste la filiation. Pour la voir, il faut d'autres
outils : **Process Hacker** et **Process Explorer**.

### Équivalents en ligne de commande (à connaître)

Quand tu n'as pas tes outils sous la main, tu dois savoir lister les processus en CLI :

| Commande | Environnement |
|---|---|
| `tasklist` | CMD |
| `Get-Process` / `ps` | PowerShell |
| `wmic process` | CMD (legacy) |

**À retenir :** le trio gagnant pour flairer un processus suspect, c'est
**nom + chemin (image path) + parent**. Task Manager te donne les deux premiers,
Process Explorer/Hacker ajoute le troisième.
