#!/usr/bin/python3
import json, time, threading, os, base64, random
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Thread_DH (threading.Thread):
    def __init__(self, dictionnaire, ip_desti, topic):
        threading.Thread.__init__(self)
        self.dictionnaire = dictionnaire
        self.ip_desti = ip_desti
        self.topic = topic
    #endef

    def run(self):
        print("########## EXECUTION D'UN THREAD##########")
        print("thread: donnees="+str(self.dictionnaire))

        #conversion du dictionnaire en json
        donneesJson = json.dumps(self.dictionnaire)
        print("thread: dictionnaire converti au format json")
        
        #envoi du message
        cmd="mosquitto_pub -h "+self.ip_desti+" -q 1 -u 1 -t "+self.topic+" -m '"+str(donneesJson)+"'"
        try:
            os.system(cmd)
        except Exception as e:
            sys.stderr.write(e.message+"\n")
            exit(1)
        print("thread: donneesJson envoyées="+str(donneesJson))
        print("########## FIN THREAD##########")
    #endef
#endclass


def on_message(client, userdata, msg):
    pass
#endef

def on_cam(client, userdata, msg):
    donnees = json.loads(msg.payload.decode("utf-8"))
    print("donnees:"+str(donnees))
    print("stationId: "+str(donnees["stationId"] ) )
    print("stationType : " +str(donnees["stationType"] ) )
    print("timestamp : " +str(donnees["timestamp"] ) )
    print("vitesse : " +str(donnees["vitesse"] ) )
    print("heading : " +str(donnees["heading"] ) )
    print("position GPS : ")
    print("latitude : " + str(donnees["positionGPS"]["latitude"]))
    print("longitude : " + str(donnees["positionGPS"]["longitude"]))
#endef

def on_denm(client, userdata, msg):
    print("\n##########DENM détecté##########")
    donnees = json.loads(msg.payload.decode("utf-8"))
    print("donnees:"+str(donnees))
#endef


def on_dh_alpha_p(client, userdata, msg):
    
    print("centralisateur: demande d'échange Diffie-Hellman  de la passerelle reçu")

     # récupérer alpha et p 
    donnees = json.loads(msg.payload.decode("utf-8"))
    print("donnees:"+str(donnees))
    alpha=donnees["alpha"]
    p=donnees["p"]


    # écriture d'alpha et p sur le disque
    f = open('alpha.txt', "w")
    f.write(str(alpha))
    f.close()

    f = open('p.txt', "w")
    f.write(str(p))
    f.close()

    print("info: alpha et p ont été récupérées")

    ip_desti="192.168.3.38"


    # générer une clé secrète b
    b=random.randint(10**1,10**3)
    print("info: clé secrète généré")

    # lecture d'alpha et p qui sont sur le disque
    f = open('alpha.txt', "r")
    var=f.read()
    alpha=int(var)
    f.close()

    f = open('p.txt', "r")
    var=f.read()
    p=int(var)
    f.close()

    print("info: début calcul clé intermédiaire")
    # calculer la clé intermédiaire Kp (K de passerelle)
    Kc= ((alpha)**b) % p
    print("info: clé intermédiaire calculée")

    # écriture de b sur le disque
    f = open('b.txt', "w")
    f.write(str(b))
    f.close()

    # création du dictionnaire contenant la clé intermédiaire
    dictionnaire = {"cle_intermediaire":Kc}

    # envoyer la clé intermédiaire au partenaire
    m = Thread_DH(dictionnaire,ip_desti,"dh/cle_intermediaire")
    print("passerelle: lancement du thread")
    m.start()

    print("info: clé intermédiaire envoyée au partenaire de l'échange")

#endef

def on_dh_cle_intermediaire(client, userdata, msg):
    print("info: dans on_dh_cle_intermediaire")

    # récupérer b qui est sur le disque 
    f = open('b.txt', "r")
    var=f.read()
    b=int(var)
    f.close()

    f = open('p.txt', "r")
    var=f.read()
    p=int(var)
    f.close()

    # récupérer la clé intermédiaire du partenaire Kp (K de la passerelle)
    donnees = json.loads(msg.payload.decode("utf-8"))
    Kp=donnees["cle_intermediaire"]

    print("info: clé intermédiaire du partenaire récupérée")

    # calculer le secret partagé
    K=(Kp**b)%p

    print("info: secret partagé K="+str(K))

    # Nettoyage
    cmd="rm b.txt p.txt alpha.txt"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    
    # écriture du secret partagé sur le disque
    f = open('secret_partage_dh.txt', "w")
    f.write(str(K))
    f.close()
    
    print("info: secret partagé DH écrit sur le disque")

#endef


if __name__ == "__main__":

    random.seed()
    
    client = mqtt.Client()
    client.on_message = on_message
    client.message_callback_add("denm/#", on_denm)
    # client.message_callback_add("dh/#", on_dh)
    client.message_callback_add("dh/alpha_p", on_dh_alpha_p)
    client.message_callback_add("dh/cle_intermediaire", on_dh_cle_intermediaire)
    
    client.connect("localhost", 1883, 60)

    client.subscribe("denm/passerelle")

    client.subscribe("dh/cle_intermediaire")
    client.subscribe("dh/alpha_p")
    

    print("info: en attente de requête")
    client.loop_forever()