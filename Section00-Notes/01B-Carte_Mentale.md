# Carte mentale – Processus Windows légitimes

Fiche de référence rapide (Core Windows Processes). 
---

## Arbre de filiation (qui lance qui)

```
System (PID 4)                     Session 0
│
└─ smss.exe                        s'auto-termine → ses enfants n'ont PAS de parent visible
   │
   ├─ csrss.exe                    Session 0   ┐ 2 instances
   ├─ csrss.exe                    Session 1   ┘ (1 par session)
   │
   ├─ wininit.exe                  Session 0
   │  ├─ services.exe
   │  │  ├─ svchost.exe (×N)       toujours lancé avec -k
   │  │  ├─ spoolsv.exe
   │  │  └─ ...
   │  └─ lsass.exe                 cible n°1 (Mimikatz / credential dumping)
   │
   └─ winlogon.exe                 Session 1
      └─ (userinit.exe)            se termine après avoir lancé le shell
         └─ explorer.exe           compte UTILISATEUR, chemin C:\Windows
```

**Clé de lecture :** `smss.exe`, `userinit.exe` se terminent après leur travail →
`csrss`, `wininit`, `winlogon`, `explorer` apparaissent **sans parent visible**,
et **c'est normal**. À l'inverse, `services.exe` → `svchost`/`lsass` ont un parent
**bien vivant** à vérifier.

---

## Tableau de référence

| Processus | PID / Instances | Parent attendu | Chemin | Compte | Session |
|---|---|---|---|---|---|
| **System** | PID **toujours 4**, 1 seule | System Idle Process (0) | `ntoskrnl.exe` | SYSTEM | 0 |
| **smss.exe** | 1 (enfants auto-terminés) | **System (4)** | `System32` | SYSTEM | 0 |
| **csrss.exe** | **2 ou +** (1/session) | smss.exe (*terminé → invisible*) | `System32` | SYSTEM | 0 et 1 |
| **wininit.exe** | 1 seule | smss.exe (*terminé → invisible*) | `System32` | SYSTEM | 0 |
| **services.exe** | 1 seule | **wininit.exe** (visible) | `System32` | SYSTEM | 0 |
| **svchost.exe** | **nombreuses** | **services.exe** | `System32` | varie (SYSTEM / Network Service / Local Service) | — |
| **lsass.exe** | **1 seule** | **wininit.exe** | `System32` | SYSTEM | 0 |
| **winlogon.exe** | 1 ou + (selon sessions) | smss.exe (*terminé → invisible*) | `System32` | SYSTEM | 1 |
| **explorer.exe** | 1 ou + par utilisateur | userinit.exe (*terminé → invisible*) | **`C:\Windows`** | **utilisateur connecté** | 1 |

---

## Points spéciaux à ne pas oublier

| Processus | Détail unique à vérifier |
|---|---|
| **System** | PID **doit** être 4 ; une seule instance |
| **csrss.exe** | le tuer = **crash système** ; 2 instances = normal |
| **svchost.exe** | ligne de commande contient **toujours `-k`** ; parent = services.exe |
| **lsass.exe** | **jamais 2 instances** ; surveiller les **accès à sa mémoire** (vol de creds) |
| **winlogon.exe** | clé registre **`Shell` doit = explorer.exe** (sinon persistance) |
| **explorer.exe** | chemin **`C:\Windows`** (PAS System32) ; **aucune** connexion réseau sortante |

---

Pour JUGER n'importe quel processus système, vérifie :

1. **Nom exact** → fautes d'orthographe = masquerading (`scvhost.exe`, `lsas.exe`, `csrsss.exe`…)
2. **Chemin (image path)** → `C:\Windows\System32` pour tous… **sauf explorer.exe** (`C:\Windows`)
3. **Parent** → correspond-il à l'arbre ci-dessus ?
4. **Compte utilisateur** → SYSTEM pour les processus système ; utilisateur connecté pour explorer.exe

Puis les cas spéciaux : **`-k`** (svchost), **clé `Shell`** (winlogon), **nombre d'instances**, **connexions réseau**.

---

## Rappel : Session 0 vs Session 1

- **Session 0** = services et processus **système** (pas d'interface graphique)
- **Session 1** (et +) = processus **utilisateur** (bureau, applis)
- Un processus système dans une session utilisateur (ou l'inverse) = **anomalie**
