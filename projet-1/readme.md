
# Projet 1

## Définitions des acteurs

* véhicule
* passerelle
* centralisateur
* autorité de certification

## Etapes  communes

### 1) Etape 0: créer le certificat autosigné de l’autorité de certification par un processus qui tourne tout le temps
(script python a réaliser sur la vm de l'autorité avec des appels système à openssl)


### 2) Etape 1: chaque véhicule connait le certificat et l'adresse ip de l'autorité


### Véhicule & Passerelle :

* génèrer une paire de clés RSA 2048
* envoyer sa clé publique à l'autorité de certification

### Autorité de certification:
* attendre de recevoir une clé publique d'un véhicule ou de la passerelle
* à la réception de la clé publique, création d'un certificat X509 (clé publique reçu + signature de cette clé avec la clé privée de l’autorité)
* envoyer le certificat x509 à l'émetteur de la clé publique précedemment reçu

## Scénario 1: Authentification (2 acteurs)
 
### Véhicule
De base chaque véhicule envoyait Data (projet de rt0707)

Data'=(Data, Empreinte SHA1 de (Data) signée avec la clé privée du véhicule, certificat X509 du véhicule)

* envoyer Data' à la passerelle

### Passerelle:

* lire les requêtes venant du véhicule
* vérifier que le certificat X509 du véhicule (qui est contenu dans ses requêtes) a bien été signé avec la clé privée de l'autorité de certification (utiliser la clé publique de l'autorité de certification pour la vérification)
* vérifier que l'empreinte SHA1 reçu a été signée avec le certificat X509 du véhicule

Pour vérifier l'authenticité du Hash SHA1 il faut:
* récupérer le certificat x509 envoyé par le véhicule
* extraire la clé publique du véhicule qui est contenu dans le certificat x509 reçu
* déchiffrer la signature envoyée par le véhicule avec la clé publique du véhicule obtenu à l'étape précédente
* calcul du hash de Data
* comparaison des 2 Hash (si les 2 sont identiques alors l'empreinte SHA1 est vérifiée)


 ## Scénario 2: Confidentialité (3 acteurs)
 
 ### Véhicule
 
 De base chaque véhicule envoyait Data (projet de rt0707)
 
 Data'=(Chiffrément AES128(Data), Empreinte SHA1 de(Data) signée avec la clé privée du véhicule, certificat X509 du véhicule)
 
* envoyer Data' à la passerelle

### Passerelle & Centralisateur

* échange de clé Diffie-Hellman entre la passerelle et le centralisateur
* chiffrement en AES 128 en utilisant la clé secrète connue par la passerelle et le centralisateur à la fin de l'échange Diffie-Hellman

