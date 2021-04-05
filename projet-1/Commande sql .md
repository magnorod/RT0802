# Installation mysql   
 
apk add mysql mysql-client  


## Initialisation  

/etc/init.d/mariadb setup  

/etc/init.d/mariadb start   


##Configuration  

Mysql_secure_installation  

1) faire ok pas de mot de passe par défaut  
2) Skip   
3) Yes (mdp : root)  
4) Yes  
5) Yes  
6) yes  
7) yes  



### Redémarrage service   

rc-service mariadb restart  

### Pour le mettre au démarrage 
 
rc-update add mariadb default  


# Répertoire  

fichier : my.cnf	chemin : /etc/mysql/my.cnf    contenu : Toutes les directives, fichier de configuration global    
fichier : mariadb-server.cnf	chemin : /etc/my.cnf.d/mariadb-server.cnf   contenu : Premier fichier de configuration global, directives principales    
fichier : .my.cnf	chemin: $ HOME	  contenu : nom d'utilisateur uniquement les directives de configuration 



## Accès a la base 

mysql -h localhost -u root

## Créer une base 

CREATE DATABASE "Nom de la base";

## Encodage
CREATE DATABASE "Nom de la base" DEFAULT CHARACTER SET ...(ex : utf8mb4);

## Supprimer une base 
DROP DATABASE "Nom de la base"; 

## Utiliser une base 
Use "Nom de la base"; 

## Creer une base 
CREATE TABLE "Nom de la table"; 

## Création table Accident
  CREATE TABLE [IF NOT EXISTS] Accident 
( id INT NOT NULL AUTO_INCREMENT, heure_accident DATETIME NOT NULL, Position FLOAT NOT NULL,  PRIMARY KEY (id) ) ENGINE=INNODB;

## Création table Embouteillage
CREATE TABLE Embouteillage  ( id INT NOT NULL AUTO_INCREMENT, heure_embouteillage DATETIME NOT NULL, Longitude FLOAT NOT NULL, id) ) ENGINE=INNODB;

## Afficher les tables 
SHOW TABLES;

## Afficher les infos dans tables 
DESCRIBE "Nom table";

 ## Supprimer une base 
DROP TABLE "nom table";