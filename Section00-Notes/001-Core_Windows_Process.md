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

---

## Partie 4 – csrss.exe (Client Server Runtime Process)

`csrss.exe` est la **face user-mode** du sous-système Windows. C'est un processus
**critique** : il tourne en permanence, et s'il est tué, c'est le **crash
complet** du système (écran bleu / arrêt). Les malwares le savent, d'où les
tentatives de se cacher derrière son nom.

- gère la **console Win32** (les fenêtres de type invite de commandes)
- s'occupe de la **création et suppression des threads** de processus
- rend l'**API Windows** disponible aux autres processus
- **mappe les lettres de lecteur** (C:, D:…)
- gère le **processus d'arrêt** de Windows (shutdown)

Pour chaque instance, il charge notamment les DLL `csrsrv.dll`, `basesrv.dll` et
`winsrv.dll`.

> Rappel de la partie précédente : `csrss.exe` (et `winlogon.exe`) sont appelés
> par `smss.exe` au démarrage pour la Session 1. Et comme il y a une instance par
> session, on en retrouve aussi un en Session 0.

### Le point clé sur le parent
`csrss.exe` est lancé par `smss.exe`… **mais** `smss.exe` s'**auto-termine** juste
après avoir créé la session. Conséquence :

> Dans Process Explorer / Hacker, `csrss.exe` apparaît **sans parent visible**
> (le parent est « mort »). **C'est normal.** Si tu vois au contraire un **vrai
> parent actif** pour csrss.exe, c'est justement ça qui est suspect.

C'est contre-intuitif pour un débutant : ici, **l'absence de parent = signe de
légitimité**.

### Comportement NORMAL

| Attribut | Valeur attendue |
|---|---|
| **Image Path** | `%SystemRoot%\System32\csrss.exe` (`C:\Windows\System32\csrss.exe`) |
| **Parent** | créé par une instance de `smss.exe`… qui s'est **auto-terminée** → pas de parent visible |
| **Instances** | **deux ou plus** (une par session : Session 0 + Session 1 au minimum) |
| **Compte** | Local System |
| **Démarrage** | quelques secondes après le boot pour les deux premières instances (Session 0 et 1). Les suivantes apparaissent à la création de nouvelles sessions — mais en général seules les sessions 0 et 1 existent |

Exemple du cours : `csrss.exe` en Session 0 (PID 392) et en Session 1 (PID 512).

### Comportement SUSPECT (red flags)

- **un vrai processus parent actif** → smss.exe appelle csrss puis s'auto-termine ;
  si csrss a un parent bien vivant, c'est anormal.
- **un chemin autre que `C:\Windows\System32`** → imposteur classique.
- **des fautes d'orthographe subtiles** dans le nom pour se faire passer pour
  csrss.exe : `csrsss.exe`, `csrss32.exe`, `csrs.exe`, un « l » minuscule à la
  place d'un « i »… → technique de **masquerading**, regarde le nom caractère par
  caractère.
- **un utilisateur autre que SYSTEM** → il doit tourner en compte SYSTEM.

`csrss.exe` = critique (le tuer = crash), chemin **System32**, compte **SYSTEM**,
**2 instances ou plus** (une par session), et surtout **pas de parent visible**
(car smss.exe s'auto-termine). Méfie-toi des **fautes d'orthographe** dans le nom.

---

## Partie 5 – wininit.exe (Windows Initialization Process)

`wininit.exe` (processus d'initialisation de Windows) est un processus **critique**
qui tourne en arrière-plan dans la **Session 0**. Son rôle principal : lancer les
grands processus système qui gèrent la sécurité et les services.

Il démarre, dans la **Session 0**, trois processus enfants importants :
- **`services.exe`** (Service Control Manager) → le gestionnaire de services
- **`lsass.exe`** (Local Security Authority Subsystem) → l'authentification et la
  sécurité (un processus très ciblé par les attaquants, car il manipule les
  identifiants)
- **`lsaiso.exe`** → associé à **Credential Guard** et **KeyGuard**

> **Note sur `lsaiso.exe` :** tu ne le verras **que si Credential Guard est
> activé**. S'il est absent, ce n'est pas une anomalie — ça veut juste dire que
> cette protection n'est pas en place sur la machine.

Retiens que `wininit.exe` est le **parent** de `services.exe` et `lsass.exe` :
ça te servira dans les parties suivantes pour vérifier leur filiation.

### Comportement NORMAL

| Attribut | Valeur attendue |
|---|---|
| **Image Path** | `%SystemRoot%\System32\wininit.exe` (`C:\Windows\System32\wininit.exe`) |
| **Parent** | créé par une instance de `smss.exe`… qui s'est **auto-terminée** → pas de parent visible |
| **Instances** | **une seule** |
| **Compte** | Local System |
| **Démarrage** | quelques secondes après le boot |

> Même logique que csrss.exe : comme `smss.exe` s'auto-termine après avoir lancé
> wininit, celui-ci apparaît **sans parent actif**. C'est normal.

### Comportement SUSPECT (red flags)

- **un vrai processus parent actif** → smss.exe l'appelle puis s'auto-termine ;
  un parent vivant = anormal.
- **un chemin autre que `C:\Windows\System32`** → imposteur.
- **des fautes d'orthographe subtiles** dans le nom (`wininlt.exe`, `winint.exe`,
  `wininit32.exe`…) → masquerading, lis le nom lettre par lettre.
- **plusieurs instances** → il ne doit y en avoir qu'**une**. Deux wininit = l'un
  est faux.
- **un utilisateur autre que SYSTEM** → il doit tourner en compte SYSTEM.

`wininit.exe` = **une** instance, chemin **System32**, compte **SYSTEM**, Session
**0**, **pas de parent visible**. C'est le **parent** de `services.exe` et
`lsass.exe` — mémorise cette filiation, c'est une clé de détection pour la suite.

---

## Partie 6 – services.exe (Service Control Manager / SCM)

`services.exe`, le **Service Control Manager (SCM)**, gère tous les **services
Windows** : il les charge, les démarre, les arrête et interagit avec eux. Un
service, c'est un programme qui tourne en arrière-plan sans interface (mises à
jour, pare-feu, antivirus, etc.).

- **charge, démarre, arrête** les services système
- maintient une **base de données** des services, interrogeable avec l'utilitaire
  natif **`sc.exe`** :

  - les infos des services sont stockées dans le registre :
  `HKLM\System\CurrentControlSet\Services`
- charge en mémoire les **pilotes (drivers)** marqués en **auto-start**
- à chaque connexion réussie d'un utilisateur, il définit la **Last Known Good
  Configuration** (`HKLM\System\Select\LastKnownGood`) — la « dernière config
  qui marchait », utilisée pour récupérer le système après un plantage

### Point clé : c'est un parent très important
`services.exe` est le **parent de nombreux processus système**, notamment :
- **`svchost.exe`** (le plus courant, on le verra juste après)
- `spoolsv.exe` (spouleur d'impression)
- `msmpeng.exe` (moteur de Windows Defender)
- `dllhost.exe`

> C'est un **nœud central** de l'arbre : beaucoup de processus légitimes doivent
> avoir `services.exe` comme parent. Si l'un d'eux (surtout `svchost.exe`) a un
> **autre parent**, c'est un signal d'alerte majeur.

### Comportement NORMAL

| Attribut | Valeur attendue |
|---|---|
| **Image Path** | `%SystemRoot%\System32\services.exe` (`C:\Windows\System32\services.exe`) |
| **Parent** | **wininit.exe** |
| **Instances** | **une seule** |
| **Compte** | Local System |
| **Démarrage** | quelques secondes après le boot |

> Différence avec les processus précédents : ici le parent **`wininit.exe` est
> bien vivant et visible** (il ne s'auto-termine pas). Donc pour services.exe, on
> **attend** un parent = wininit.exe.

### Comportement SUSPECT (red flags)

- **un parent autre que wininit.exe** → la filiation attendue est brisée.
- **un chemin autre que `C:\Windows\System32`** → imposteur.
- **des fautes d'orthographe subtiles** dans le nom (`service.exe`,
  `sevices.exe`, `services32.exe`…) → masquerading.
- **plusieurs instances** → il ne doit y en avoir qu'**une**.
- **un utilisateur autre que SYSTEM** → il doit tourner en compte SYSTEM.
- 
`services.exe` = le **SCM**, **une** instance, chemin **System32**, compte
**SYSTEM**, parent **wininit.exe** (bien visible cette fois). C'est le **parent**
de `svchost.exe`, `spoolsv.exe`, etc. — une filiation centrale à vérifier.

---

## Partie 7 – svchost.exe (Host Process for Windows Services)

`svchost.exe` (Service Host) héberge et gère les **services Windows**. C'est l'un
des processus les plus importants à connaître, car il est **omniprésent** (de
nombreuses instances tournent en permanence) et **très ciblé** par les attaquants.

Les services hébergés par svchost sont implémentés sous forme de **DLL** (et non
d'exécutables autonomes). La DLL à charger est indiquée dans le registre, sous la
clé : HKLM\SYSTEM\CurrentControlSet\Services\NOM_DU_SERVICE\Parameters

- `-k` sert à **regrouper des services similaires** pour qu'ils partagent le même
  processus → c'est un choix de conception pour **réduire la consommation de
  ressources**.
- la valeur après `-k` (ici `DcomLaunch`) indique le **groupe de services**.

> **Évolution à connaître :** depuis **Windows 10 version 1703**, sur les machines
> avec **plus de 3,5 Go de RAM**, chaque service tourne dans **son propre
> processus** svchost (au lieu d'être regroupé). C'est pour ça que tu vois
> **énormément** d'instances de svchost.exe sur un Windows 10/11 moderne — c'est
> normal.

> **Red flag majeur :** un `svchost.exe` **sans paramètre `-k`** dans sa ligne de
> commande est hautement suspect. Un vrai svchost en a toujours un. Vérifie
> **toujours** la `Command line`.

### Pourquoi c'est une cible privilégiée
Comme il y a toujours plein de svchost.exe, un malware peut **se fondre dans la
masse**. Les tactiques classiques des attaquants :
- **nommer le malware `svchost.exe`** pour se cacher parmi les légitimes
- **une faute d'orthographe** légère : `scvhost.exe`, `svch0st.exe`, `svhost.exe`…
- **installer/appeler un service (DLL) malveillant** via un vrai svchost

### Comportement NORMAL

| Attribut | Valeur attendue |
|---|---|
| **Image Path** | `%SystemRoot%\System32\svchost.exe` (`C:\Windows\System32\svchost.exe`) |
| **Parent** | **services.exe** |
| **Instances** | **nombreuses** (plein, c'est normal) |
| **Compte** | **variable** : SYSTEM, Network Service ou Local Service selon l'instance. Sous Windows 10, certaines tournent même sous l'utilisateur connecté |
| **Démarrage** | souvent quelques secondes après le boot, mais d'autres instances peuvent démarrer **plus tard** (à la demande) |
| **Ligne de commande** | contient **toujours `-k`** |

### Comportement SUSPECT (red flags)

- **un parent autre que services.exe** → le vrai svchost est TOUJOURS lancé par
  services.exe. C'est le red flag n°1 pour ce processus.
- **un chemin autre que `C:\Windows\System32`** → imposteur.
- **des fautes d'orthographe** (`scvhost.exe`, `svch0st.exe`…) → masquerading.
- **l'absence du paramètre `-k`** dans la ligne de commande → quasi certain d'être
  malveillant.
  
`svchost.exe` = héberge des services (des **DLL**), **beaucoup** d'instances
(normal), chemin **System32**, parent **services.exe**, et **toujours `-k`** dans
la ligne de commande. Les 4 vérifs réflexes : **parent = services.exe**, **chemin
System32**, **orthographe exacte**, **présence du `-k`**.

---

## Partie 8 – lsass.exe (Local Security Authority Subsystem Service)

`lsass.exe` (LSASS) applique la **politique de sécurité** du système. C'est un
processus **ultra-sensible** car il manipule les identifiants des utilisateurs.
Il est responsable de :
- **vérifier les connexions** des utilisateurs (ouverture de session)
- gérer les **changements de mot de passe**
- créer les **jetons d'accès (access tokens)** — qui définissent les droits d'un
  utilisateur sur le système
- écrire dans le **journal de sécurité** Windows (Security Log)

Il crée les jetons de sécurité pour **SAM** (Security Account Manager, la base des
comptes locaux), **AD** (Active Directory, pour les environnements de domaine) et
**NETLOGON**. Il utilise les **packages d'authentification** définis dans :
```
HKLM\System\CurrentControlSet\Control\Lsa
```

### Pourquoi c'est une cible de choix (très important pour un SOC)
`lsass.exe` garde en mémoire des **identifiants** (hashes de mots de passe, tickets
Kerberos…). C'est donc **LA cible n°1** pour le vol de credentials :
- des outils comme **Mimikatz** servent à **dumper les identifiants** directement
  depuis la mémoire de lsass.exe
- les attaquants **imitent** aussi lsass.exe pour se cacher (même nom ou faute
  d'orthographe légère)

> Réflexe SOC : toute **lecture de la mémoire de lsass.exe** par un processus
> inhabituel, ou un accès au « LSASS process dump », est un signal d'alerte fort
> (tentative de vol d'identifiants). C'est un des comportements les plus
> surveillés en détection.

### Comportement NORMAL

| Attribut | Valeur attendue |
|---|---|
| **Image Path** | `%SystemRoot%\System32\lsass.exe` (`C:\Windows\System32\lsass.exe`) |
| **Parent** | **wininit.exe** |
| **Instances** | **une seule** |
| **Compte** | Local System |
| **Démarrage** | quelques secondes après le boot |

### Comportement SUSPECT (red flags)

- **un parent autre que wininit.exe** → filiation brisée.
- **un chemin autre que `C:\Windows\System32`** → imposteur.
- **des fautes d'orthographe** : `lsas.exe`, `lsass.exe`, `ls@ss.exe`,
  `lsass32.exe`… → masquerading très courant sur ce nom.
- **plusieurs instances** → il ne doit y en avoir qu'**une**. Deux lsass = l'un
  est faux (red flag classique : un faux `lsass.exe` à côté du vrai).
- **un utilisateur autre que SYSTEM** → il doit tourner en compte SYSTEM.

`lsass.exe` = sécurité et **identifiants**, **une** instance, chemin **System32**,
compte **SYSTEM**, parent **wininit.exe**. Cible privilégiée de Mimikatz → surveille
les **accès à sa mémoire** et les **doublons** / **fautes d'orthographe**.

---

## Partie 9 – winlogon.exe (Windows Logon)

`winlogon.exe` gère **l'ouverture de session utilisateur**. C'est le processus qui
s'occupe de tout ce qui entoure la connexion d'un utilisateur à son environnement.

- gère la **Secure Attention Sequence (SAS)** : la combinaison **Ctrl+Alt+Suppr**
  que l'utilisateur presse pour saisir son identifiant et son mot de passe. Cette
  séquence existe pour des raisons de sécurité (empêcher un faux écran de login de
  capturer le mot de passe).
- **charge le profil utilisateur** : il charge le fichier **`NTUSER.DAT`** de
  l'utilisateur dans la ruche de registre **`HKCU`** (HKEY_CURRENT_USER)
- déclenche **`userinit.exe`**, qui lui charge le **shell** de l'utilisateur
  (c'est-à-dire `explorer.exe`, le bureau)
- gère le **verrouillage de l'écran** et l'**économiseur d'écran**

> Rappel : `winlogon.exe` est lancé par `smss.exe` en **Session 1** (en même temps
> qu'une copie de `csrss.exe`). C'est la branche **côté utilisateur**.

### La chaîne de connexion à retenir

winlogon.exe → userinit.exe → explorer.exe (le bureau de l’utilisateur)

`userinit.exe` fait son travail puis se **termine** — c'est pour ça qu'ensuite
`explorer.exe` apparaîtra lui aussi **sans parent visible**.

### Comportement NORMAL

| Attribut | Valeur attendue |
|---|---|
| **Image Path** | `%SystemRoot%\System32\winlogon.exe` (`C:\Windows\System32\winlogon.exe`) |
| **Parent** | créé par une instance de `smss.exe` qui s'est **terminée** → pas de parent visible |
| **Instances** | **une ou plus** |
| **Compte** | Local System |
| **Démarrage** | quelques secondes après le boot pour la première instance (Session 1). D'**autres instances** apparaissent à la création de nouvelles sessions (bureau à distance / RDP, changement rapide d'utilisateur) |

> Pourquoi « une ou plus » ? Chaque session interactive (une connexion RDP, un
> deuxième utilisateur en Fast User Switching) a **son** winlogon. Donc plusieurs
> winlogon.exe n'est pas forcément suspect — ça dépend du nombre de sessions
> ouvertes.

### Comportement SUSPECT (red flags)

- **un vrai processus parent actif** → smss.exe l'appelle puis s'auto-termine ;
  un parent vivant = anormal.
- **un chemin autre que `C:\Windows\System32`** → imposteur.
- **des fautes d'orthographe** (`winlogin.exe`, `winlog0n.exe`…) → masquerading.
- **un utilisateur autre que SYSTEM** → il doit tourner en compte SYSTEM.
- **une valeur `Shell` dans le registre autre que `explorer.exe`** → red flag
  important. La clé `Shell`
  (`HKLM\...\Winlogon\Shell`) doit valoir `explorer.exe`. Si un attaquant y met
  autre chose, son programme sera lancé à **chaque connexion** → technique de
  **persistance** classique (« Winlogon Shell hijack »).

`winlogon.exe` = ouverture de session + Ctrl+Alt+Suppr, chemin **System32**,
compte **SYSTEM**, **pas de parent visible**, **une ou plus** (selon les sessions).
Vérifie la clé registre **`Shell` = explorer.exe** : c'est un point de persistance
surveillé.

---

## Partie 10 – explorer.exe (Windows Explorer)

`explorer.exe` est l'**interface graphique** de l'utilisateur : il donne accès aux
**dossiers et fichiers**, et fournit le **menu Démarrer** et la **barre des
tâches**. C'est, en gros, « le bureau » Windows.

Souviens-toi de la chaîne de connexion : `winlogon.exe` lance `userinit.exe`, qui
lit la valeur `Shell` du registre
(`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` = `explorer.exe`)
et démarre `explorer.exe`. Ensuite **`userinit.exe` se termine**.

> Conséquence (comme pour csrss/winlogon) : le parent de `explorer.exe` est
> **mort**, donc **pas de parent visible** dans les outils d'analyse. **C'est
> normal.**

### ⚠️ Le piège du chemin (à bien retenir)
Contrairement à TOUS les autres processus vus jusqu'ici, `explorer.exe` ne se
trouve **PAS** dans `System32` :

| Processus | Chemin attendu |
|---|---|
| Tous les précédents | `C:\Windows\System32\...` |
| **explorer.exe** | **`C:\Windows\explorer.exe`** (= `%SystemRoot%`, directement) |

Donc pour explorer.exe, un chemin dans `C:\Windows\System32` serait justement
**anormal**. Attention à ne pas te tromper de règle.

### Comportement NORMAL

| Attribut | Valeur attendue |
|---|---|
| **Image Path** | `%SystemRoot%\explorer.exe` (`C:\Windows\explorer.exe`) |
| **Parent** | créé par `userinit.exe`… qui se **termine** → pas de parent visible |
| **Instances** | **une ou plus par utilisateur connecté** de façon interactive |
| **Compte** | **l'utilisateur connecté** (PAS SYSTEM cette fois) |
| **Démarrage** | à la **première ouverture de session interactive** |

> Deux différences par rapport aux processus système : il tourne sous le **compte
> de l'utilisateur** (normal, c'est son bureau), et il a **beaucoup de processus
> enfants** (toutes les applis que l'utilisateur lance depuis le bureau ont
> explorer.exe comme parent).

### Comportement SUSPECT (red flags)

- **un vrai processus parent actif** → userinit.exe l'appelle puis se termine ;
  un parent vivant = anormal.
- **un chemin autre que `C:\Windows`** → imposteur (ex. un explorer.exe dans un
  dossier temp ou utilisateur).
- **un utilisateur inconnu** → il doit tourner sous un utilisateur légitime
  connecté.
- **des fautes d'orthographe** (`explorere.exe`, `expl0rer.exe`…) → masquerading.
- **des connexions TCP/IP sortantes** → `explorer.exe` n'a **pas** de raison de
  communiquer sur le réseau. Des connexions sortantes depuis explorer.exe =
  signal fort (souvent du **code injecté** dans le processus pour sortir
  discrètement vers un C2).

`explorer.exe` = le bureau, chemin **`C:\Windows`** (pas System32 !), compte
**utilisateur connecté**, **pas de parent visible**, beaucoup d'enfants. Red flags
spécifiques : **mauvais chemin**, **connexions réseau sortantes**.

---

