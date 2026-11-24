Conclusion – Résumé de l'attaque (Boogeyman 2)

L'incident Boogeyman 2 marque le retour du groupe Boogeyman contre Quick Logistics
LLC. Cette fois, la cible est Maxine Beck, employée des ressources humaines. Le
groupe a fait évoluer ses techniques : il remplace l'archive piégée de Boogeyman 1 par
un document Office contenant une macro, et l'investigation s'appuie principalement
sur l'analyse d'un dump mémoire au lieu des logs PowerShell et d'une capture réseau.

Accès initial (Initial Access) – Spear phishing
Maxine reçoit un e-mail de candidature intitulé « Resume - Application for Junior
IT Analyst Role », envoyé depuis westaylor23@outlook.com. Le prétexte est crédible
pour quelqu'un aux RH. La pièce jointe est un faux CV, Resume_WesleyTaylor.doc.
Exécution (Execution) – Macro VBA (stage 1)
L'analyse du document avec olevba révèle une macro AutoOpen() qui s'exécute
dès l'ouverture du fichier. Elle utilise Microsoft.XMLHTTP pour télécharger
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png,
l'enregistre sous C:\ProgramData\update.js à l'aide de Adodb.Stream, puis
l'exécute avec wscript.exe via WScript.Shell.
→ Le fichier .png est en réalité un script JavaScript : l'extension sert de
camouflage.
Exécution – Stage 2 → binaire final
Le script update.js télécharge à son tour update.exe depuis le même dossier
du serveur de l'attaquant. Dans le dump mémoire (windows.pstree), ce binaire
apparaît sous le nom C:\Windows\Tasks\updater.exe, lancé comme enfant de
wscript.exe. Le dossier Tasks est souvent inscriptible et peu surveillé.
Command & Control (C2)
windows.netstat / windows.netscan montrent que updater.exe établit une
connexion vers le C2 128.199.95.189:8080. Grâce à ce canal, l'attaquant
exécute des commandes sur le poste, qu'on peut retrouver avec windows.cmdline
et par strings sur la mémoire du process.
Persistance (Persistence) – Tâche planifiée + registre
L'attaquant crée une tâche planifiée Updater (schtasks /Create /SC DAILY /ST 09:00), qui lance PowerShell en mode caché. Ce PowerShell lit une charge
encodée en base64 stockée dans la valeur de registre debug de
HKCU\Software\Microsoft\Windows\CurrentVersion, puis l'exécute avec IEX.
→ La charge réside dans le registre et non sur disque, ce qui la rend plus
discrète face aux outils qui ne surveillent que les fichiers.
Impact
L'attaquant garde un accès persistant et à distance au poste de Maxine.
L'exécution est relancée chaque jour, même après un redémarrage, et la machine
peut servir de point d'entrée pour la suite de l'attaque (mouvement latéral,
vol de données).

Bilan : un simple CV piégé a suffi à mettre en place une chaîne d'infection en
trois étapes (macro → JavaScript → binaire) puis une persistance discrète. Chaque
étape cherche à passer inaperçue : extension .png trompeuse, emplacements système
légitimes (ProgramData, Windows\Tasks), nom de binaire anodin (updater.exe) et
charge cachée dans le registre. Le cas montre l'intérêt de l'analyse mémoire :
une grande partie des preuves (stage 2, URL de update.exe, connexion C2, commandes)
n'existait qu'en RAM. La réponse à incident impose d'isoler le poste, de supprimer
la tâche planifiée et la clé de registre, de bloquer le domaine et l'IP du C2, et de
renforcer la politique d'exécution des macros Office.

Artefacts clés de l'investigation : e-mail de phishing (Resume - Application for Junior IT Analyst Role.eml), document malveillant (Resume_WesleyTaylor.doc), dump
mémoire (WKSTN-2961.raw).

Outils utilisés : olevba (extraction de la macro), Volatility 3 (pstree,
cmdline, netstat/netscan, filescan, memmap), strings + grep.
