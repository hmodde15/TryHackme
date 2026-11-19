# Core Windows Processes – Notes de révision

## Partie 1 – Task Manager

### À quoi ça sert
Task Manager est l'utilitaire graphique **natif** de Windows (présent sur TOUTES
les machines) qui liste les processus en cours et leur consommation de ressources
(CPU, mémoire). On s'en sert pour dépanner (tuer un programme planté) mais aussi,
en analyse SOC, pour inspecter rapidement ce qui tourne sur un poste.

Pour l'ouvrir : clic droit sur la barre des tâches → **Task Manager**, puis clique
sur **More details** (sinon tu ne vois presque rien).

### Notion de PID (process identifier)
Chaque fois qu'un programme démarre, Windows lui attribue un **numéro unique**,
le PID  :
- si un même programme tourne en plusieurs exemplaires (ex. plusieurs onglets
  Chrome), **chaque instance a son propre PID**.
- les PID sont attribués **dans l'ordre de démarrage** et de façon globalement
  aléatoire… **sauf** quelques processus système à PID fixe (on le verra avec
  System = PID 4).

### Les colonnes à ajouter (clic droit sur l'en-tête des colonnes)
Par défaut Task Manager montre peu de choses. Pour faire de l'analyse, ces trois
colonnes sont essentielles :

| Colonne | Ce que c'est | Pourquoi c'est crucial |
|---|---|---|
| **PID** | l'identifiant du processus | pour le retrouver/corréler avec d'autres outils |
| **Image path name** | le **chemin complet** de l'exécutable sur le disque | un processus légitime a un chemin attendu (ex. `C:\Windows\System32\`). Un `svchost.exe` lancé depuis `C:\Users\...\Downloads\` = très suspect |
| **Command line** | la **commande complète** de lancement (avec ses arguments) | révèle les URL, scripts, options cachées. C'est souvent là qu'on voit l'intention malveillante |

> L'idée clé : un malware se **déguise** souvent en processus Windows légitime
> (même nom). Mais s'il tourne depuis le mauvais dossier ou avec une ligne de
> commande bizarre, le déguisement tombe. D'où l'importance de `Image path name`
> et `Command line`.

### La grande faiblesse de Task Manager
Task Manager **ne montre PAS la relation parent-enfant** entre les processus.
Or, savoir **quel processus en a lancé un autre** est un critère de détection
majeur.

Exemple concret : `svchost.exe` devrait toujours être lancé par
`services.exe`. Dans Task Manager on voit un `svchost.exe` avec le PID 384 et
`services.exe` avec le PID 632. Ça semble absurde (l'enfant 384 « avant » le
parent 632 ?) — en réalité Task Manager **masque juste la filiation**, il ne la
trie pas par hiérarchie. Pour voir qui est le parent de qui, il faut d'autres
outils : **Process Explorer** et **Process Hacker** (ils affichent l'arbre
parent → enfant). C'est pour ça qu'on les utilisera à la place de Task Manager
dans la suite.

### Les équivalents en ligne de commande (à connaître absolument)
Un jour tu seras sur une machine sans tes outils graphiques. Tu dois savoir
lister les processus en CLI :

| Commande | Où |
|---|---|
| `tasklist` | invite de commandes (CMD) |
| `Get-Process` (alias `ps`) | PowerShell |
| `wmic process` | CMD (ancienne méthode, encore vue) |

Pour juger si un processus est suspect, le trio gagnant c'est :
**nom + chemin de l'exécutable (image path) + processus parent.**
Task Manager te donne les deux premiers ; Process Explorer / Hacker ajoute le
troisième (le parent), le plus parlant pour détecter un intrus.

---

## Partie 2 – System (PID 4)

`System` est un processus **très particulier**. Contrairement aux autres, son PID
n'est pas aléatoire : il est **toujours égal à 4**. Retiens ce chiffre, c'est un
repère de détection.

Pour comprendre System, il faut la distinction **user mode / kernel mode** :

- **User mode** : l'espace « bac à sable » où tournent les applications normales
  (ton navigateur, Word…). Accès **limité** : une appli ne peut pas toucher
  directement le matériel ou la mémoire des autres. Si elle plante, elle ne fait
  pas tomber tout le système.
- **Kernel mode** : le niveau **privilégié**, au cœur de Windows. Accès **total**
  au matériel (CPU, RAM, disques) et à toute la mémoire. C'est là que tourne le
  noyau (`ntoskrnl.exe` = *NT OS Kernel*) et les pilotes (drivers).

Le processus `System` est la « maison » des **threads en mode noyau** : des fils
d'exécution qui tournent uniquement en kernel mode, pour faire fonctionner le cœur
de l'OS et les drivers. Il n'a **pas d'espace mémoire utilisateur** : il puise sa
mémoire directement dans les réserves du système d'exploitation.

> En clair : `System`, c'est l'activité interne du **noyau** de Windows,
> regroupée sous un processus visible nommé « System » avec le PID 4.

### Comportement NORMAL

| Attribut | Valeur attendue | Remarque |
|---|---|---|
| **PID** | **toujours 4** | jamais autre chose |
| **Image Path** | `C:\Windows\system32\ntoskrnl.exe` | affiché par Process Hacker ; Process Explorer montre « N/A » — les deux sont « corrects », c'est juste une différence d'affichage entre outils |
| **Parent** | **System Idle Process (PID 0)** | ou aucun parent réel. Le PID 0 est un pseudo-processus Windows |
| **Instances** | **une seule** | il n'existe qu'un seul System |
| **Compte** | Local System | le compte le plus privilégié |
| **Démarrage** | au **boot** (démarrage machine) | il est là depuis le tout début |
| **Session** | **Session 0** | la session réservée aux services/système |

> Process Hacker affiche souvent `System` en **vert** et marqué **Verified**
> (signé Microsoft) : un bon indice de légitimité (mais pas une preuve absolue,
> une signature peut être usurpée dans de rares cas).

### Comportement SUSPECT (les red flags)
Un attaquant essaie parfois de se cacher derrière le nom « System ». Voici ce qui
doit t'alerter, et **pourquoi** :

- **un parent autre que System Idle Process (0)** → le vrai System n'est lancé par
  rien d'autre ; un parent inhabituel = imposteur.
- **plusieurs instances de System** → il ne doit y en avoir qu'**une**. Deux
  « System » = l'un est faux.
- **un PID différent de 4** → si tu vois un processus nommé System avec un PID
  genre 3948, c'est un malware qui a juste repris le nom.
- **un processus qui ne tourne pas en Session 0** → le vrai System est en Session 0
  (côté système). Un « System » dans une session utilisateur est suspect.

`System` = PID **4**, **une** instance, parent **PID 0**, **Session 0**, lancé au
boot, lié au noyau (`ntoskrnl.exe`). Toute déviation sur un de ces points mérite
une analyse approfondie.

Windows isole les processus dans des **sessions**. La **Session 0** est réservée
aux **services et processus système** (pas d'interface graphique, par sécurité).
Les processus **utilisateur** (ton `explorer.exe`, tes applis) tournent en
**Session 1** (ou plus). Règle de détection : un processus **système** qui
apparaît dans une session utilisateur — ou un processus utilisateur en Session 0 —
est une **anomalie** à creuser.

---

## Partie 3 – smss.exe (Session Manager Subsystem)

`smss.exe`, le **Session Manager Subsystem** (gestionnaire de sessions Windows),
est responsable de la **création des nouvelles sessions**. Point important : c'est
le **tout premier processus en mode utilisateur (user-mode)** lancé par le noyau.
Autrement dit, juste après le noyau et `System`, c'est lui qui démarre.

`smss.exe` met en route le sous-système Windows, à cheval sur les deux modes :
- côté **kernel mode** : `win32k.sys`
- côté **user mode** : `winsrv.dll` et `csrss.exe`

Concrètement, il lance les processus de base de **chaque session** :
- **Session 0** (côté système) : il démarre `csrss.exe` et `wininit.exe`
- **Session 1** (côté utilisateur) : il démarre `csrss.exe` et `winlogon.exe`

> **Le mécanisme malin à retenir :** l'instance « maître » de `smss.exe` se
> **copie elle-même** dans chaque nouvelle session pour la créer, puis
> **s'auto-termine** (l'enfant disparaît tout seul). C'est pour ça qu'en temps
> normal tu ne vois qu'**un seul** `smss.exe` qui persiste : les copies enfants
> ont déjà fini leur travail et se sont fermées.

### Ses autres responsabilités
- créer les **variables d'environnement**
- gérer les **fichiers de pagination** de la mémoire virtuelle (virtual memory
  paging files)
- lancer `winlogon.exe` (le gestionnaire d'ouverture de session Windows)
- lancer tout sous-système listé dans la valeur `Required` de la clé de registre :
  `HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems`

### Comportement NORMAL

| Attribut | Valeur attendue |
|---|---|
| **Image Path** | `%SystemRoot%\System32\smss.exe` (soit `C:\Windows\System32\smss.exe`) |
| **Parent** | **System (PID 4)** |
| **Instances** | **une** instance maître + une instance enfant **par session**, mais les enfants **se ferment** après avoir créé leur session → en pratique, **une seule** visible |
| **Compte** | Local System (SYSTEM) |
| **Démarrage** | quelques **secondes après le boot** (pour l'instance maître) |

### Comportement SUSPECT (red flags)

- **un parent autre que System (4)** → le vrai smss est toujours lancé par System.
- **un chemin différent de `C:\Windows\System32`** → un `smss.exe` ailleurs
  (ex. dans un dossier utilisateur ou temp) = imposteur classique.
- **plus d'un processus smss.exe persistant** → les enfants s'auto-terminent ;
  si tu vois plusieurs `smss.exe` qui restent, c'est anormal.
- **un utilisateur autre que SYSTEM** → il doit tourner en compte SYSTEM.
- **des entrées de registre inattendues** dans la clé `Subsystems` → un attaquant
  peut y ajouter un sous-système malveillant pour qu'il soit lancé au démarrage
  (technique de persistance).

`smss.exe` = **premier processus user-mode**, parent **System (4)**, chemin
**System32**, compte **SYSTEM**, et **une seule** instance visible (les enfants
se ferment). Il crée les sessions et lance `csrss.exe` / `wininit.exe` (Session 0)
et `csrss.exe` / `winlogon.exe` (Session 1).

