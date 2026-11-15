# Machine totalement compromise (Fully-Owned Machine)

L'attaquant a désormais obtenu les privilèges administrateur sur la machine. Il faut identifier toutes les techniques de persistance utilisées par l'attaquant.

Par ailleurs, les exécutions inhabituelles sont liées au binaire C2 malveillant utilisé lors de l'élévation de privilèges.

## Guide d'investigation

On peut maintenant s'appuyer sur notre cheatsheet pour investiguer les événements qui suivent une élévation de privilèges réussie :

* Filtre Brim utile pour récupérer toutes les requêtes HTTP liées au trafic C2 malveillant : `_path=="http" "<remplacer domaine>" id.resp_p==<remplacer port> | cut ts, host, id.resp_p, uri | sort ts`
* L'attaquant a obtenu les privilèges SYSTEM ; désormais, le contexte utilisateur de chaque exécution malveillante se fond dans `NT Authority\System`.
* Tous les événements enfants (child events) du nouveau binaire malveillant utilisé pour le C2 méritent d'être examinés.

### Question :

1 - Après avoir obtenu un accès de niveau SYSTEM, l'attaquant a créé deux utilisateurs. Quels sont les noms de ces comptes ? 
Format : Réponse par ordre alphabétique, séparée par des virgules

On sais que la création d'un utilisateur déclenche un event 4720. On utilise donc un filtre sur cet event :

