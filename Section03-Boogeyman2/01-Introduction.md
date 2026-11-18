# Boogeyman 2

Après une attaque sévère menée par le Boogeyman, Quick Logistics LLC a renforcé ses défenses de sécurité. Mais le Boogeyman revient avec des tactiques, techniques et procédures nouvelles et améliorées.

Dans cette room, tu vas devoir analyser les nouvelles tactiques, techniques et procédures (TTP) du groupe malveillant nommé **Boogeyman**.

## Plateforme d'investigation

Avant de commencer, déploie la machine jointe en cliquant sur le bouton **Start Lab Machine** en haut à droite de la tâche. L'initialisation des services peut prendre de 3 à 5 minutes.

La machine démarre en vue partagée (split-screen). Si la VM n'est pas visible, utilise le bouton bleu **Show Split View** en haut à droite de la page.

### Artefacts

Pour l'investigation, les artefacts suivants te sont fournis :

* Copie de l'e-mail de phishing.
* Dump mémoire (memory dump) du poste de travail de la victime.

Ces fichiers se trouvent dans le répertoire `/home/ubuntu/Desktop/Artefacts`.

### Outils

La VM fournie contient les outils suivants :

* **Volatility** — un [framework open-source](https://github.com/volatilityfoundation/volatility3) pour extraire des artefacts numériques depuis des échantillons de mémoire volatile (RAM).

```shell-session
ubuntu@tryhackme$ # Utilisation de Volatility :
ubuntu@tryhackme$ vol -f memorydump.raw <plugin>

# Pour lister tous les plugins disponibles
ubuntu@tryhackme$ vol -f memorydump.raw -h
```

> Note : Volatility peut prendre quelques minutes pour parser le dump mémoire et exécuter le plugin. Pour la référence des plugins, consulte la [documentation](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.html) de Volatility 3.

* **Olevba** — un outil pour analyser et extraire les macros VBA des documents Microsoft Office. Cet outil fait partie de la suite [Oletools](https://github.com/decalage2/oletools).

```shell-session
ubuntu@tryhackme$ # Utilisation d'Olevba :
ubuntu@tryhackme$ olevba document.doc
```
