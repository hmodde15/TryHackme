# Cheatsheet – Analyse d'un en-tête d'e-mail (phishing)

Mémo pour l'analyse des headers d'e-mail en investigation phishing (SOC).

---

## Principe

Un e-mail = **headers** (métadonnées techniques) + **body** (contenu).
Les headers racontent le trajet du mail, serveur par serveur.

> Règle d'or : les champs du **haut** sont les plus **récents**.
> On lit de **bas en haut** pour suivre la chronologie.

---

## 1. Champs d'identité (facilement falsifiables)

Déclarés par l'expéditeur → un attaquant peut mettre ce qu'il veut. À vérifier, pas à croire.

| Champ | Ce qu'il dit | Piège |
|---|---|---|
| `From` | expéditeur affiché | **spoofable** : le nom affiché peut cacher une autre adresse |
| `To` | destinataire | parfois vide/générique (envoi en masse) |
| `Reply-To` | où part la réponse | **drapeau rouge** s'il diffère du `From` |
| `Return-Path` | où reviennent les rebonds (bounces) | souvent le **vrai** domaine d'envoi |
| `Subject` | objet | — |
| `Date` | date déclarée | peut être incohérente avec les `Received` |

**1er réflexe :** comparer `From` / `Reply-To` / `Return-Path`.
Domaines différents = suspect.

---

## 2. Champs `Received` (le trajet réel)

Chaque serveur relais ajoute sa ligne `Received` **en haut**.

- `Received` le plus **bas** = point de **départ** (serveur de l'expéditeur) → **IP source d'origine**
- `Received` le plus **haut** = dernier serveur avant ta boîte

Exemple :

```
Received: from mail.attaquant.com (mail.attaquant.com [203.0.113.5])
          by mx.quicklogistics.com with ESMTP id abc123
          for <maxine@quicklogistics.com>; Wed, 18 Nov 2025 10:00:00
```

- `from ...` → qui prétend envoyer + **IP réelle** entre crochets `[203.0.113.5]`
- `by ...` → serveur qui a reçu
- l'IP de la ligne la plus basse = ton **meilleur IOC**

---

## 3. Champs d'authentification (la preuve)

Plus durs à falsifier que le `From`. Dans `Authentication-Results`.

| Mécanisme | Vérifie | Résultats |
|---|---|---|
| **SPF** | l'IP d'envoi est-elle autorisée pour ce domaine ? | `pass` / `fail` / `softfail` |
| **DKIM** | signature crypto : mail modifié ? | `pass` / `fail` |
| **DMARC** | combine SPF + DKIM + alignement du domaine | `pass` / `fail` |

Exemple :

```
Authentication-Results: mx.quicklogistics.com;
    spf=fail (sender IP is 203.0.113.5) smtp.mailfrom=attaquant.com;
    dkim=fail; dmarc=fail
```

`spf=fail` + `dkim=fail` + `dmarc=fail` sur un mail « interne » ou « partenaire » = fort signal de spoofing.

⚠️ Un SPF `pass` ne veut PAS dire « mail sûr » : juste que l'IP est autorisée pour **ce** domaine.
Un attaquant depuis son propre domaine aura un `pass` légitime. `pass` + domaine bizarre = quand même suspect.

---

## 4. Méthode (dans l'ordre)

1. Comparer `From` / `Reply-To` / `Return-Path` → cohérents ?
2. Lire les `Received` de bas en haut → **IP source d'origine**
3. Vérifier `Authentication-Results` → SPF / DKIM / DMARC
4. Extraire les IOC : IP d'origine, domaine expéditeur, liens + pièces jointes du body
5. Pivoter : IP et domaine dans AbuseIPDB, VirusTotal, etc.

---

## 5. Outils

**Thunderbird** → ouvrir le `.eml`, puis *More → View Source* pour les headers bruts.

**Ligne de commande :**

```bash
# voir les headers (début du fichier)
head -n 40 dump.eml

# isoler les champs d'identité
grep -iE "^(From|To|Reply-To|Return-Path|Subject|Date):" dump.eml

# suivre le trajet
grep -i "^Received:" dump.eml
```

**En ligne :** Google *Messageheader*, MXToolbox *Email Header Analyzer*.

---

## Rappel : extraire une pièce jointe encodée (base64)

Souvent la pièce jointe est en base64 en bas du `.eml`.

```bash
# récupérer la chaîne base64 dans un fichier puis décoder
cat payload_b64.txt | base64 -d > piece_jointe.ext
```

Ensuite, selon le type : `olevba` (macros Office), `file` (identifier), etc.
