# Cheatsheet – Investigation des logs sous Linux (SOC)

Mémo des journaux et commandes pour l'analyse d'un système Linux compromis.

---

## Où sont les logs

La plupart sont dans **`/var/log/`**. Les noms varient selon la distribution
(Debian/Ubuntu vs RHEL/CentOS).

| Fichier | Contenu | Distro |
|---|---|---|
| **`/var/log/auth.log`** | authentification, sudo, SSH | Debian/Ubuntu |
| **`/var/log/secure`** | authentification, sudo, SSH | RHEL/CentOS |
| `/var/log/syslog` | journal système général | Debian/Ubuntu |
| `/var/log/messages` | journal système général | RHEL/CentOS |
| `/var/log/kern.log` | messages du noyau | — |
| `/var/log/cron` | tâches planifiées (cron) | — |
| `/var/log/faillog` | échecs de connexion | — |
| `/var/log/apache2/` ou `/var/log/httpd/` | logs web (access.log, error.log) | — |
| `/var/log/btmp` | échecs de connexion (binaire → `lastb`) | — |
| `/var/log/wtmp` | connexions réussies (binaire → `last`) | — |
| `/var/log/utmp` | sessions actuellement ouvertes (→ `who`) | — |

---

## Les fichiers clés à connaître

### Authentification (`auth.log` / `secure`)
Le plus important en SOC. On y voit :
- connexions **SSH** réussies / échouées
- usage de **`sudo`**
- création d'utilisateurs, changements de mot de passe

```bash
# échecs de connexion SSH (brute force ?)
grep "Failed password" /var/log/auth.log

# connexions SSH réussies
grep "Accepted password\|Accepted publickey" /var/log/auth.log

# usage de sudo
grep "sudo:" /var/log/auth.log

# création d'utilisateurs / groupes
grep -iE "useradd|usermod|groupadd" /var/log/auth.log
```

### Comptes système
```bash
/etc/passwd    # liste des comptes (UID 0 = root → en chercher d'autres !)
/etc/shadow    # mots de passe hashés
/etc/sudoers   # qui peut faire sudo
```

```bash
# chercher des comptes avec UID 0 (= root) autres que root → backdoor
awk -F: '$3 == 0 {print $1}' /etc/passwd
```

### Historique des commandes
```bash
~/.bash_history          # commandes tapées par un utilisateur
/root/.bash_history      # commandes de root
cat ~/.bash_history
```

### Persistance à vérifier
```bash
crontab -l               # tâches cron de l'utilisateur
cat /etc/crontab         # cron système
ls -la /etc/cron.*       # cron.daily, cron.hourly...
systemctl list-units --type=service   # services (persistance via systemd)
ls -la ~/.ssh/authorized_keys          # clés SSH ajoutées (backdoor)
```

---

## Commandes d'investigation

### Qui s'est connecté
```bash
last            # connexions réussies (lit wtmp)
lastb           # connexions échouées (lit btmp) → brute force
who             # sessions actuellement ouvertes
w               # sessions + ce que font les utilisateurs
lastlog         # dernière connexion de chaque compte
```

### journalctl (systemd — moderne)
```bash
journalctl                       # tout le journal
journalctl -u ssh                # logs d'un service précis
journalctl --since "1 hour ago"  # fenêtre de temps
journalctl -p err                # uniquement les erreurs
journalctl -f                    # suivre en direct
```

### auditd (si installé — audit avancé)
```bash
ausearch -m USER_LOGIN           # recherche par type d'événement
aureport                         # rapports synthétiques
```

---

## Boîte à outils texte (le cœur de l'analyse)

| Commande | Rôle |
|---|---|
| `grep -i "motif" fichier` | rechercher (insensible à la casse) |
| `grep -E "a\|b\|c"` | plusieurs motifs (OU) |
| `tail -f fichier` | suivre un log en temps réel |
| `tail -n 100` | les 100 dernières lignes |
| `less fichier` | lire en paginé |
| `awk` | extraire/filtrer des colonnes |
| `cut -d: -f1` | découper par délimiteur |
| `sort \| uniq -c` | compter les occurrences |
| `wc -l` | compter les lignes |

### Exemples combinés utiles

```bash
# Top des IP qui ont tenté de se connecter en SSH (brute force)
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

# Compter les échecs par utilisateur ciblé
grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -nr

# Toutes les commandes sudo exécutées
grep "COMMAND=" /var/log/auth.log
```

---

## La démarche type

1. **Authentification** (`auth.log`/`secure`) → qui s'est connecté, d'où, brute force ?
2. **Comptes** (`/etc/passwd`, UID 0) → compte suspect / backdoor ?
3. **Historique** (`.bash_history`) → qu'a fait l'attaquant ?
4. **Persistance** (cron, services, clés SSH) → comment reste-t-il ?
5. **Réseau / web** (logs apache, connexions) → vecteur d'entrée, C2 ?
6. **Corréler les temps** → reconstituer la timeline de l'attaque

> ⚠️ Un attaquant peut **effacer ou modifier** les logs (`/var/log` vidé,
> `.bash_history` supprimé). L'absence de logs est elle-même un indice. En
> forensic poussée, on travaille sur une **copie** du disque, pas sur le système live.
