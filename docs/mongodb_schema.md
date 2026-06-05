# MongoDB Schema — Cowrie Honeypot IDS

## Collections Cowrie (générées automatiquement)

### sessions
- src_ip : IP source de l'attaquant
- dst_port : port de destination (2222)
- timestamp : horodatage UTC
- starttime / endtime : durée de session
- sshversion : version SSH du client attaquant

### auth
- src_ip : IP source
- username : identifiant tenté
- password : mot de passe tenté
- eventid : cowrie.login.failed / cowrie.login.success

### input
- src_ip : IP source
- input : commande tapée par l'attaquant
- eventid : cowrie.command.input / cowrie.command.failed

### ttylog
- ttylog : session complète en binaire hex
- shasum : hash de vérification
- duration : durée de la session

## Collections Module IA (générées par notre daemon)

### ip_scores
- ip : adresse IP analysée
- score : score de risque [0-100] calculé par Random Forest
- categorie : normal / suspect / malveillant
- statut : normale / surveillee / bloquee
- nb_tentatives : nombre total de tentatives

### decisions
- ip : IP analysée
- score_rf : score Random Forest
- decision : IGNORER / SURVEILLER / BLOQUER
- raisonnement : explication LLM en français
- timestamp : horodatage UTC

### actions
- ip : IP ciblée
- type : BLOCAGE / DEBLOCAGE
- source : auto_ia / admin_manuel / admin_chat
- succes : true/false
- commande_nftables : règle appliquée sur VM Firewall

### whitelist
- ip : IP en liste blanche permanente
- raison : raison de l'ajout
- ajoute_par : admin / admin_chat

### faux_positifs
- ip : IP signalée comme faux positif
- raison : raison du signalement