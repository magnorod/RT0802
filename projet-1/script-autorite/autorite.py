#!/usr/bin/python3
import json, os, subprocess, threading
import paho.mqtt.client as mqtt

class Thread (threading.Thread):

    def __init__(self, csr, ip_demandeur_certificat):
        threading.Thread.__init__(self)
        self.csr = csr
        self.ip_demandeur_certificat = ip_demandeur_certificat
    #endef

    def run(self):
        
        print("\n##########EXECUTION D'UN THREAD##########")
        print("thread : csr\n"+str(self.csr))
        print("thread : ip_demandeur_certificat\n"+str(self.ip_demandeur_certificat))
        
        # créer un fichier temporaire contenant la clé publique recu
        cmd= 'echo "'+self.csr+'" > csr_recu.pem' 
        
        try:
            os.system(cmd)
        except Exception as e:
            print(e.message)
        
        print("thread: fichier temporaire créé")
        #endif

        # générer le certificat à partir de la clé publique reçu qui sera signée avec la clé privée de l'autorité
        signer_certificat("csr_recu.pem")

        # envoyer le certif
        envoyer_certificat(self.ip_demandeur_certificat,"certificatX509","public-produit.crt")
    #endef

def envoyer_certificat(ip_desti,topic,certificat):

    #envoyer le certificat x509 qui a été généré à la cible 
    ip_desti=ip_desti[0:len(ip_desti)-4]


    # création d'un dictionnaire qui va contenir le certificat
    certificat=subprocess.check_output(["cat", "public-produit.crt"])
    certificat=certificat.decode()
    certificat=str(certificat)

    print("info: certificat")
    print(certificat)
    dictionnaire = {"certificatX509":certificat}

    #conversion du dictionnaire en json
    json_data=json.dumps(dictionnaire)

    cmd="mosquitto_pub -h "+str(ip_desti)+" -q 1 -u autorite -t config/"+str(topic)+" -m '"+str(json_data)+"'"
    print(cmd)

    try:
        os.system(cmd)
    except Exception as e:
        print(e.message)
    print("info: certificat X509 envoyé au demandeur")
#endef

def on_message(client, userdata, msg):
    pass
#endef


def on_config(client, userdata, msg):
    donnees = json.loads(msg.payload.decode("utf-8"))
    cle_publique_json=str(donnees["csr"] )
    ip_demandeur_certificat=str(donnees["ip_demandeur_certificat"] )

     # à la réception d' une clé publique lancement d'un thread pour s'occuper de la génération du certificat X509 à partir de cette clé publique 
    m = Thread(cle_publique_json,ip_demandeur_certificat)
    m.start()

#endef

def signer_certificat(csr):
    # signature du certificat
    cmd="openssl x509 -req -days 365 -in "+csr+" -signkey keypair.pem -out public-produit.crt"
    try:
        os.system(cmd)
    except Exception as e:
        print(e.message)
    print("info: certificat X509 signé par l'autorité")

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
        
        # création du fichier Certificate Signing Request (CSR) avec la clé privée
        cmd="openssl req -new -key "+fichier_pem+" -out csr.pem -batch"

        try:
            os.system(cmd)
        except Exception as e:
            print(e.message)

        print("info: fichier csr créé")

        # signature du certificat
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

    generer_certificat_autorite("keypair.pem")
    
    #attente d'une clé publique d'un véhicule ou de la station
    client = mqtt.Client()
    client.on_message = on_message
    client.message_callback_add("config/#", on_config)
    client.connect('127.0.0.1', 1883, 60)
    client.subscribe("config/csr")
    print("info: en attente d'une demande de certificat X509")
    client.loop_forever()

   
#endif