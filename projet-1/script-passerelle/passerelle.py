#!/usr/bin/python3
import json, time, threading, os, sys, subprocess, base64
import paho.mqtt.client as mqtt

class MonThread (threading.Thread):
    def __init__(self, donnees):
        threading.Thread.__init__(self)
        self.donnees = donnees
    #endef

    def run(self):
        print("##########EXECUTION D'UN THREAD##########")
        print("THREAD:donnees="+str(self.donnees))
        #conversion du dictionnaire en json
        donneesJson = json.dumps(self.donnees)
        cmd1="mosquitto_pub -h 192.168.0.54 -q 1 -u passerelle -t denm/passerelle -m '"+str(donneesJson)+"'"
        os.system(cmd1)
        print("THREAD: cmd1="+str(cmd1))
        print("THREAD:denm envoyé au centralisateur")
    #endef

def generer_cles_rsa(fichier_pem):

    # on vérifie si la paire de clés existe déja
    if os.path.exists(fichier_pem) == False:

        # création de la paire de  clés RSA 2048
        cmd="openssl genrsa -out "+fichier_pem+" 2048"
        try:
            os.system(cmd)
        except Exception as e:
            print(e.message)
        
        print("info: paire de clés RSA 2048 créé")
    else:
        print("info: la paire de clés RSA existe déja ")
    #endif
        
#endef

def recuperer_cle_publique(keypair,cle_pub):

    cmd="openssl rsa -in "+keypair+" -pubout -out "+cle_pub
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: clé publique extraite")
#endef


def verifier_hash(hash_file,signature,certificatx509,cle_pub_certificat):

    print("info: TEST VERIF SIGNATURE")


    #cmd="openssl rsautl -in "+signature+" -verify -pubin -inkey "+cle_pub_certificat
    cmd="openssl dgst -verify "+cle_pub_certificat+" -keyform PEM -sha1 -signature "+signature+" -binary message.txt"
    
    print(cmd)
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
#endef

def on_message(client, userdata, msg):
    pass

def on_cam(client, userdata, msg):
    donnees = json.loads(msg.payload.decode("utf-8"))
    #print("info: données recu:"+str(donnees))

    # dictionnaire={"data":dictionnaire_data,"signature":dictionnaire_signature,"certificat":dictionnaire_certificat}


    # récupération des 3 éléments
    data=donnees["data"]
    certificat=donnees["data"]
    signature=donnees["signature"]


    print("\n")
    print("data:")
    print(data)

    print("\n")
    print("certificat")
    print(certificat)

    print("\n")
    print("signature")
    print(signature)


    # désencoder base64
    signature_binaire=base64.b64decode(signature["signature_base64_binaire"])

    print("\n")
    print("signature binaire")
    print(signature_binaire)

    # écriture binaire de la signature

    f = open('signature-recu.sig', "wb")
    f.write(signature_binaire)
    f.close()

    print("\n")
    print("info: base64 signature recu:")
    print(signature["signature_base64_binaire"])


#endef
def on_denm(client, userdata, msg):
    print("\n##########DENM détecté##########")
    donnees = json.loads(msg.payload.decode("utf-8"))
    print("donnees:"+str(donnees))
    stationType=int(donnees["stationType"])
    print("stationType:"+str(stationType))
    ## tout évènement provenant d'un opérateur routier est remonté au centralisateur
    if stationType == 15:
        #remonter info à passerelle
        print("lancement du thread")
        m = MonThread(donnees)
        # crée un thread
        m.start()
        print("ok")
    #endif

    """
    # prise en compte des accidents

    cmpt_signalement_accident=0
    latitude_accident=0
    longitude_accident=0
    tab_timestamp_accident=[]
    
    ## vérifie si 2 véhicules standard ont signalé un accident durant les 10 dernières minutes
    
    elif stationType != 15 and cause == 4:

    # ajout du timestamp du véhicule
    tab_timestamp_accident.append(timestamp)

    # ajout de la position de l'accident signalé

    if cmpt_signalement_accident == 0:
        latitude_accident=latitude
        longitude_accident=longitude
    #endif

    difference_timestamp=(nouveau_timestamp) - (tab_timestamp_accident[0])
    if (difference_timestamp<! 600 ) # < à 10 minutes
        #prise en compte du signalement
        cmpt_signalement_accident+=1
        tab_timestamp_accident.append(timestamp)

        # il ya bien un accident
        if cmpt_signalement_accident == 2:
            cmpt_signalement_accident=0
            tab_timestamp_accident.pop(0)
            tab_timestamp_accident.pop(1)
            envoyer msg au centralisateur
        #endif

    #endif

    # prise en compte des embouteillages
    cmpt_signalement_embouteillage=0
    latitude_embouteillage=0
    longitude_embouteillage=0
    tab_timestamp_embouteillage=[]
    elif stationType != 15 and cause == 5:
        # ajout du timestamp du véhicule
        tab_timestamp_embouteillage.append(timestamp)
    """
#endef

def timestamp_hhmmss(timestamp):
    tmp = int(timestamp.split(".")(0))
    ss = tmp % 60
    mm = tmp / 60 - tmp
    hh = tmp / (24 * 60) - tmp
    return (hh,mm,ss)
#endef

def appartient_plage_horaire(plage, t1):
    res = False
    h1, m1, s1 = timestamp_hhmmss(plage)
    h2, m2, s2 = timestamp_hhmmss(t1)
#endef

def generer_csr(fichier_pem,csr):

    # création du fichier Certificate Signing Request (CSR)
    cmd="openssl req -new -key "+fichier_pem+" -out "+csr+" -batch"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    print("info: fichier csr créé")
#endef
def generer_json_csr(fichier_csr):


    cmd="cat "+fichier_csr
    try:
        var=subprocess.check_output(cmd, shell = True)
        var=var.decode()
        var=str(var)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    # récupération de l'ip de l'acteur demandant un certificat
    cmd="ip addr show | grep enp0s3 | grep inet | awk '{print $2}'"
    try:
        var2=subprocess.check_output(cmd, shell = True)
        var2=var2.decode()
        var2=str(var2)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    if var and var2 : # vérifie si var et var2 existent

        # création d'un dictionnaire
        dictionnaire = {"csr": var, "ip_demandeur_certificat":var2}

        #conversion du dictionnaire en json
        json_data=json.dumps(dictionnaire)

        # cmd="rm "+fichier_csr
        # print("SUPPRESSION:"+cmd)
        # try:
        #     os.system(cmd)
        # except Exception as e:
        #     sys.stderr.write(e.message+"\n")
        #     exit(1)

        return json_data
    #endif

   
#endef

def envoyer_csr(csr,ip_server_mqtt):

    cmd="mosquitto_pub -h "+str(ip_server_mqtt )+" -q 1 "+"-u vehicule -t config/csr -m '"+str(csr)+"'" 
    #print(cmd)
    
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    print("info: csr envoyé à l'autorité de certification")
    #endif
    
#endef

def on_config(client, userdata, msg):
    donnees = json.loads(msg.payload.decode("utf-8"))
    certificat=str(donnees["certificatX509"] )

    # print("info: donnees")
    # print(certificat)

    # écriture du certificat dans un fichier
    cmd="echo \""+certificat+"\" > certificatx509.crt"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    
    print("info: le certificatX509 a été récupéré ")

#endef

if __name__ == "__main__":

    fichier_paire_de_cles="keypair.pem"
    ip_autorite="192.168.3.26"
    fichier_signature="hash.sig"
    cle_pub_certificat="pubx509.pem"
    cle_pub="pub.pem"
    fichier_csr="csr.pem"
    certificat="certificatx509.crt"

    generer_cles_rsa(fichier_paire_de_cles)
    recuperer_cle_publique(fichier_paire_de_cles,cle_pub)
    generer_csr(fichier_paire_de_cles,fichier_csr)
    csr_json=generer_json_csr(fichier_csr)
    envoyer_csr(csr_json,ip_autorite)

    client = mqtt.Client()
    client.on_message = on_message

    client.message_callback_add("cam/#", on_cam)
    client.message_callback_add("denm/#", on_denm)
    client.message_callback_add("config/#", on_config)

    client.connect('127.0.0.1', 1883, 60)

    client.subscribe("config/certificatX509")
    client.subscribe("cam/auto")
    client.subscribe("cam/moto")
    client.subscribe("cam/camion")
    client.subscribe("denm/auto")
    client.subscribe("denm/moto")
    client.subscribe("denm/camion")

    print("info: attente de requêtes des véhicules")
    client.loop_forever()
