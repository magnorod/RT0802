#!/usr/bin/python3
import json, time, threading, os, base64
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Thread_DH (threading.Thread):
    def __init__(self, donnees, ip_desti, topic):
        threading.Thread.__init__(self)
        self.donnees = donnees
        self.ip_desti = ip_desti
        self.topic = topic
    #endef

    def run(self):
        
        print("##########EXECUTION D'UN THREAD##########")

        print("thread(passerelle): donnees="+str(self.donnees))
        print("thread(passerelle): ip_desti="+str(self.ip_desti))

        print("cle_publique_dh="+str(self.donnees))
        # cle_publique_dh_b64_bytes=base64.b64encode(self.donnees)
        # cle_publique_dh_b64=cle_publique_dh_b64_bytes.decode("ascii")


         # création du dictionnaire
        dictionnaire = {"cle_publique_dh":self.donnees}

        #conversion du dictionnaire en json
        donneesJson = json.dumps(dictionnaire)
        cmd="mosquitto_pub -h "+self.ip_desti+" -q 1 -u 1 -t "+self.topic+" -m '"+str(donneesJson)+"'"
        try:
            os.system(cmd)
        except Exception as e:
            sys.stderr.write(e.message+"\n")
            exit(1)

        print("thread(passerelle): cmd="+str(cmd))
        print("thread(passerelle): clé publique Diffie Hellman envoyée à la passerelle")

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


def on_dh(client, userdata, msg):

    print("centralisateur: demande d'échange Diffie-Hellman  de la passerelle reçu")
    ip_desti="192.168.3.38"



    # Generate some parameters. These can be reused.
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    #Generate a private key for use in the exchange.
    private_key = parameters.generate_private_key()


    donnees = json.loads(msg.payload.decode("utf-8"))
    print("donnees:"+str(donnees))
    peer_public_key=str(donnees["peer_public_key"])
    print("centralisateur: Kp récupéré")

    # envoyer la clé publique au centralisateur via un thread
    print("passerelle: thread créé")
    m = Thread_DH(private_key.public_key(),ip_desti,"dh/centralisateur")
    print("passerelle: lancement du thread")
    m.start()


    # secret_partagé
    shared_key = private_key.exchange(peer_public_key)

    ## Perform key derivation
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        ).derive(shared_key)

    print("centralisateur: K="+str(derived_key))
#endef


if __name__ == "__main__":
    
    client = mqtt.Client()
    client.on_message = on_message
    client.message_callback_add("denm/#", on_denm)
    client.message_callback_add("dh/#", on_dh)
    client.connect("localhost", 1883, 60)

    client.subscribe("denm/passerelle")

    # Diffie Hellman avec la passerelle
    client.subscribe("dh/passerelle")
    print("info: en attente de requête")
    client.loop_forever()