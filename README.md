<div align="center">

# SAL1 — Exercices finaux SOC Analyst Level 1

**Mes notes et ma démarche d'analyse pour les exercices finaux de la certification [SAL1](https://tryhackme.com) de TryHackMe**

![TryHackMe](https://img.shields.io/badge/TryHackMe-SAL1-212C42?style=for-the-badge&logo=tryhackme&logoColor=white)
![Blue Team](https://img.shields.io/badge/Blue_Team-SOC_L1-1E90FF?style=for-the-badge)
![Statut](https://img.shields.io/badge/Statut-En_cours-F5A623?style=for-the-badge)

</div>

---

## Objectif

Garder une trace de ma démarche d'analyse et m'en servir pour réviser.

> **L'idée : documenter la méthodologie plus que les réponses.**
> Une bonne réponse sans raisonnement ne sert à rien le jour où l'alerte est différente.

Chaque exercice suit le cycle de traitement d'une alerte en SOC :

```
  Alerte  ──►  Triage  ──►  Investigation  ──►  Escalade / Clôture
```

---

## Organisation

Chaque exercice est documenté selon la même structure :

| Section | Contenu |
|:--|:--|
| **Contexte** | Le scénario et l'alerte de départ |
| **Investigation** | Les étapes suivies et les outils utilisés |
| **Réponses** | Ce qui a été trouvé et les conclusions |

<details>
<summary><b>Voir le modèle utilisé pour chaque exercice</b></summary>

```markdown
# Exercice XX — <Nom>

## Contexte
- **Scénario :**
- **Alerte de départ :**
- **Sévérité initiale :**

## Investigation
1. Triage : vrai positif / faux positif ?
2. Étapes d'analyse
3. Outils utilisés :
4. IOC relevés (IP, domaines, hashes, comptes) :

## Réponses
- Ce qui a été trouvé :
- Conclusion :
- Décision : escalade / clôture, et pourquoi
```

</details>

---

## Avertissement

Ce dépôt a un but **personnel et pédagogique**. Il sert à structurer mes révisions, pas à fournir des réponses toutes faites : la valeur est dans la démarche.
