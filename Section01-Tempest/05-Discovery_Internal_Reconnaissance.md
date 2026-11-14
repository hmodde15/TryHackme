# Reconnaissance interne
 
D'après les éléments collectés, on a découvert que le **binaire malveillant utilise en continu le trafic C2** :
 
- On peut facilement **décoder la chaîne encodée** dans le trafic réseau.
- Le trafic contient les **commandes exécutées par l'attaquant et leur résultat**.
## Guide d'investigation
 
Pour poursuivre l'investigation, on peut se concentrer sur les informations suivantes :
 
- Recherchez les **événements réseau et processus** qui se connectent au domaine malveillant.
- Recherchez les **événements réseau contenant une commande encodée**.
- On peut utiliser **Brim** pour filtrer tous les paquets contenant la chaîne encodée.
- Cherchez des **commandes d'énumération du poste**, puisque l'attaquant est déjà à l'intérieur de la machine.
On peut aussi se référer à l'aide-mémoire Brim pour analyser rapidement le trafic encodé avec le filtre suivant :
 
- Pour obtenir toutes les requêtes HTTP liées au trafic C2 malveillant :
```
_path=="http" "<domaine>" id.resp_p==<port> | cut ts, host, id.resp_p, uri | sort ts
```
### Question

1 - L'attaquant a réussi à découvrir un fichier sensible sur la machine de l'utilisateur. Quel est le mot de passe découvert dans ce fichier ?

On utilise la commande donné pour récupérer les requetes : _path=="http" "resolvecyber.xyz" id.resp_p==80 | cut ts, host, id.resp_p, uri | sort ts

![Tryhackme](00-Images/file.png)

On décode ensuite les requetes en base64 afin de décoder le trafic :

