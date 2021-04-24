#!/usr/bin/python3
import hashlib, random, time, sys, os, subprocess, json
import paho.mqtt.client as mqtt

# initialisation graine random
random.seed()

def generer_cles_rsa(fichier_pem):

    # on vérifie si la paire de clés existe déja
    if os.path.exists(fichier_pem) == False:

        # création de la paire de  clés RSA 2048
        cmd="openssl genrsa -out "+fichier_pem+" 2048"
        try:
            os.system(cmd)
        except Exception as e:
            sys.stderr.write(e.message+"\n")
            exit(1)

        
        print("info: paire de clés RSA 2048 créé")
    else:
        print("info: la paire de clés RSA existe déja ")
    #endif
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

def gen_stationId():

     # récupération hostname (auto,moto,camion)
    hostname = subprocess.check_output(['hostname'])
    hostname=hostname.decode()
    hostname=str(hostname)

    # corrélation entre le hostname et le stationId
    if "auto" in hostname :
        stationId=1
    elif "moto" in hostname :
        stationId=2
    else: 
        # camion
        stationId=3
    #endif

    return stationId
#endef


def gen_json_cam(stationId,stationType,vitesse,heading,latitude,longitude,timestamp):

    #msg_cam = '{"stationId":'+str(stationId)+',"stationType":'+str(stationType)+',"timestamp":'+str(timestamp)+',"vitesse":'+str(vitesse)+',"heading":'+str(heading)+',"positionGPS":{"longitude":'+str(longitude)+',"latitude":'+str(latitude)+'}'+'}'
    
    
    
    #print(certificat)
    dictionnaire_positionGPS = {"longitude":longitude,"latitude":latitude}
    dictionnaire = {"stationId":stationId,"stationType":stationType,"timestamp":timestamp,"vitesse":vitesse, "heading":heading, "positionGPS":dictionnaire_positionGPS }

    #conversion du dictionnaire en json
    json_data=json.dumps(dictionnaire)
    print("info: json via dictionnaire")
    print(dictionnaire)
    
    return json_data

#endef

def gen_json_denm(stationId,stationType,cause,sub_cause,latitude,longitude,timestamp):

    msg_denm =  '{"stationId":'+str(stationId)+',"stationType":'+str(stationType)+',"timestamp":'+str(timestamp)+',"cause":'+str(cause)+',"sub-cause":'+str(sub_cause)+',"positionGPS":{"longitude":'+str(longitude)+',"latitude":'+str(latitude)+'}'+'}'
    return msg_denm

#endef

def gen_msg_cam(stationId,stationType,longitude,latitude,vitesse,ip_server_mqtt,timestamp):

    # génération heading
    heading = random.randint(-360,360)
    msg_cam = gen_json_cam(stationId,stationType,vitesse,heading,latitude,longitude,timestamp)


    # construction requête bash
    topic=""
    if stationId == 1:
        topic="auto"
    elif stationId == 2:
        topic="moto"
    else:
        topic="camion"

    cmd="mosquitto_pub -h "+str(ip_server_mqtt)+" -q 1 "+"-u "+str(stationId)+" -t cam/"+str(topic)+" -m '"+str(msg_cam)+"'" 
    print(cmd)

    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    
    return msg_cam

#endef

def gen_msg_denm(stationId,stationType,longitude,latitude,vitesse,ip_server_mqtt,timestamp):

    # génération cause
    cause_tab=(3,4,5,6,7)
    cause_string=("travaux","accident","embouteillage","route glissante","brouillard")
    topic=""
    
    # opérateur signale un èvenement (acteur de confiance)
    if stationType == 15:
        choix_cause=random.randint(0,len(cause_tab)-1)
        cause=cause_tab[choix_cause]
        cause_txt=cause_string[choix_cause]
        print("opérateur signale un evenement "+str(cause_txt))
    #endif
    
    # un véhicule standard signale un embouteillage
    elif stationType != 15 and vitesse <= 30:
            cause = 5
            print("un véhicule standard signale un"+str(cause_string[2]))
    #endif

    # un véhicule standard signale un évènement
    elif stationType != 15:
        choix_cause=random.randint(0,len(cause_tab)-1)
        cause=cause_tab[choix_cause]
        cause_txt=cause_string[choix_cause]
        print("un véhicule standard signale evenement "+str(cause_txt))
    #endif

    # génération sub-cause
    sub_cause=random.randint(1,10)
    msg_denm=gen_json_denm(stationId,stationType,cause,sub_cause,latitude,longitude,timestamp)

    # construction requête 
    if stationId == 1:
        topic="auto"
    elif stationId == 2:
        topic="moto"
    else:
        topic="camion"
    #endif

    cmd="mosquitto_pub -h "+str(ip_server_mqtt)+" -q 1 "+"-u "+str(stationId)+" -t denm/"+str(topic)+" -m '"+str(msg_denm)+"'"
    print(cmd)
    

    try:
        os.system(cmd)

    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    return msg_denm

#endef 

def on_config(client, userdata, msg):
    donnees = json.loads(msg.payload.decode("utf-8"))
    certificat=str(donnees["certificatX509"] )

    print("info: donnees")
    print(certificat)

    # écriture du certificat dans un fichier
    cmd="echo \""+certificat+"\" > certificatx509.crt"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    
    print("info: le certificatX509 a été récupéré ")

#endef

def on_message(client, userdata, msg):
    pass
#endef

def choix_scenario():

    scenario=input("info: choisir un scénario (1 ou 2) \n")

    if scenario != '1' and scenario != '2':
        sys.stderr.write("erreur: choisir le scénario 1 ou 2 \n")
        exit(1)
    #endif

    return scenario
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


def recuperer_cle_publique_certificat(certificatx509,cle_pub_certificat):
    cmd="openssl x509 -pubkey -noout -in "+certificatx509+" > "+cle_pub_certificat
    print(cmd)
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
#endef

def scenario1_envoyer_cam(json_data,signature_du_hash_de_data,certificat,stationId,stationType,vitesse,heading,latitude,longitude,timestamp):
    
    #construction du message CAM
    dictionnaire_positionGPS = {"longitude":longitude,"latitude":latitude}
    dictionnaire_data = {"stationId":stationId,"stationType":stationType,"timestamp":timestamp,"vitesse":vitesse, "heading":heading, "positionGPS":dictionnaire_positionGPS }
    
    # récupération de la signature
    fichier = open(signature_du_hash_de_data, "r")
    var=fichier.read()
    fichier.close()
    
    # ajout de la signature au dictionnaire
    dictionnaire_signature={"signature":str(var)}


    # récupération du certificat
    fichier = open(certificat, "r")
    var=fichier.read()
    fichier.close()

    # ajout du certificat au dictionnaire
    dictionnaire_certificat={"certificat":str(var)}

    # ajout du dictionnaire global
    dictionnaire={"data":dictionnaire_data,"signature":dictionnaire_signature,"certificat":dictionnaire_certificat}

    #conversion du dictionnaire en json
    json_data=json.dumps(dictionnaire)
    print("info: json via dictionnaire")
    print(dictionnaire)
    
    return json_data
#endef


def signer_hash_sha1_message(message,fichier_paire_de_cles):


    #création d'un fichier tmp
    cmd="echo "+message+" > message.txt"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    cmd="openssl dgst -sign "+fichier_paire_de_cles+" -keyform PEM -sha1 -out hash.sig -binary message.txt"
    print(cmd)
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
#endef 



if __name__ == '__main__' :


    #definitions des variables
    fichier_paire_de_cles="keypair.pem"
    ip_autorite="192.168.3.22"
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
    client.message_callback_add("config/#", on_config)
    client.connect('127.0.0.1', 1883, 60)
    client.subscribe("config/certificatX509")
    
    client.loop_start()
    time.sleep(1)
    client.loop_stop()


    scenario=choix_scenario()

    stationId=gen_stationId()
    stationType_tab=(5,10,15)
    ip_passerelle="192.168.1.21"
    frequence_cam=0
    longitude_base= 4.0333
    latitude_base=49.25
    cmpt_tour_boucle=0
    variation_degre_1km_longitude= 0.01
    variation_degre_1km_latitude= 0.008
        
    while True :

        # génération stationType
        choix_stationType=random.randint(0,len(stationType_tab)-1)
        stationType=stationType_tab[choix_stationType]

        # génération vitesse
        if stationId == 2 :
            vitesse = random.randint(90,130)
        elif stationId == 3:
            vitesse = random.randint(0,90)
        else:
            vitesse = random.randint(0,130)
        #endif

        if vitesse < 90 :
            frequence_cam=1 # 1sec
        else:
            frequence_cam=0.100 #0,1
        #endif

        distance_parcourue=((vitesse/3.6)*frequence_cam)/1000
        longitude=longitude_base+(distance_parcourue*variation_degre_1km_longitude)
        latitude=latitude_base+(distance_parcourue*variation_degre_1km_latitude)

        timestamp=time.time()
        
        
        if scenario == '1':
            
            print("info: scénario authentification")
            
            # Construction du message
            msg_cam = gen_json_cam(stationId,stationType,longitude,latitude,vitesse,ip_passerelle,timestamp)

            print("msg_cam:")
            print(msg_cam)

            #Signature du hash sha1 du message
            signer_hash_sha1_message(msg_cam,fichier_paire_de_cles)

            # envoi
            scenario1_envoyer_cam(msg_cam,fichier_signature,certificat,stationId,stationType,longitude,latitude,vitesse,ip_passerelle,timestamp)

             # envoi d'un message denm à une fréquence de 1/10 de la fréquence d'envoi des msg CAM
            if cmpt_tour_boucle == 10:
                msg_denm = gen_msg_denm(stationId,stationType,longitude,latitude,vitesse,ip_passerelle,timestamp)
                print(msg_denm)
                cmpt_tour_boucle=0
            #endif

            print("envoi à une fréquence de "+str(frequence_cam))
            print(msg_cam)
            cmpt_tour_boucle+=1
            time.sleep(frequence_cam)

        else : #scenario=2
            print("info: scénario confidentialité")
        #endif



        #msg_cam = gen_msg_cam(stationId,stationType,longitude,latitude,vitesse,ip_server_mqtt,timestamp)

       
    #end
#endif

   
    
    



    
