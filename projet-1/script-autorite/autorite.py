#!/usr/bin/python3
import json, os, subprocess, threading
import paho.mqtt.client as mqtt

class Thread (threading.Thread):

    def __init__(self, donnees):
        threading.Thread.__init__(self)
        self.donnees = donnees
    #endef

    def run(self):
        print("##########EXECUTION D'UN THREAD##########")
        # print("THREAD:donnees="+str(self.donnees))
        # #conversion du dictionnaire en json
        # donneesJson = json.dumps(self.donnees)
        # cmd1="mosquitto_pub -h 192.168.0.54 -q 1 -u passerelle -t denm/passerelle -m '"+str(donneesJson)+"'"
        # os.system(cmd1)
        # print("THREAD: cmd1="+str(cmd1))
        # print("THREAD:denm envoyé au centralisateur")
    #endef

def recevoir_cle_publique():
    donnees = json.loads(msg.payload.decode("utf-8"))
    print("donnees:"+str(donnees))
    cle_publique=str(donnees["cle_publique"])

    # envoi sous forme json  donneesJson = json.dumps(self.donnees)
    envoyer_certificat(ip_desti,"cle_publique",cle_publique)
#endef

def envoyer_certificat(ip_desti,topic,certificat):
    #envoyer le certificat x509 qui a été généré à la cible 
    print("")
    cmd1="mosquitto_pub -h "+str(ip_desti)+" -q 1 "+"-u  autorite -t config/"+str(topic)+" -m '"+str(certificat)+"'"
    os.system(cmd1)

#endef

def on_message(client, userdata, msg):
    pass
#endef


def on_config(client, userdata, msg):
    donnees = json.loads(msg.payload.decode("utf-8"))
    print("donnees:"+str(donnees))
    print("cle_publique: "+str(donnees["cle_publique"] ) )
#endef



def generer_certificat_autorite(fichier_pem):

    if os.path.exists(fichier_pem) == False: # on vérifie si la paire de clés existe déja

        # création de la paire de  clés RSA 2048
        cmd="openssl genrsa 2048 > "+fichier_pem
        try:
            os.system(cmd)
        except Exception as e:
            print(e.message)
        
        print("info: paire de clé ok")
        
        # création du fichier CSR avec la clé privée
        cmd="openssl req -new -key "+fichier_pem+" -out csr.pem -batch"

        try:
            os.system(cmd)
        except Exception as e:
            print(e.message)

        print("info: fichier csr créé")

        #Génération à partir de la clé privée et du csr du certificat public.crt 
        cmd="openssl x509 -req -days 365 -in csr.pem -signkey "+fichier_pem+" -out public.crt"
        try:
            os.system(cmd)
        except Exception as e:
            print(e.message)

        print("info: certificat X509 créé")

    else:
        print("info: le certificat X509 de l autorite existe deja")
    #endif
#endef



if __name__ == '__main__' :

    generer_certificat_autorite("privatekey.pem")
    
    #attente d'une clé publique d'un véhicule ou de la station
    client = mqtt.Client()
    client.on_message = on_message
    client.message_callback_add("config/#", on_config)
    client.connect('127.0.0.1', 1883, 60)
    client.subscribe("config/cle-publique")


    # à la réception d' une clé publique lancement d'un thread pour s'occuper de la génération du certificat X509 à partir de cette clé publique 
    # m = Thread(cle_publique)
    # m.start()


    client.loop_forever()

   
#endif