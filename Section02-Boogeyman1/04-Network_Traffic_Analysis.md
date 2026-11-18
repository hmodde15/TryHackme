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

