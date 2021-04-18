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

def generer_csr(fichier_pem):

    # création du fichier Certificate Signing Request (CSR)
    cmd="openssl req -new -key "+fichier_pem+" -out csr.pem -batch"
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

        return json_data
    #endif
#endef

def envoyer_csr(csr,ip_server_mqtt):

    cmd="mosquitto_pub -h "+str(ip_server_mqtt )+" -q 1 "+"-u vehicule -t config/csr -m '"+str(csr)+"'" 
    print(cmd)
    
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

    msg_cam = '{"stationId":'+str(stationId)+',"stationType":'+str(stationType)+',"timestamp":'+str(timestamp)+',"vitesse":'+str(vitesse)+',"heading":'+str(heading)+',"positionGPS":{"longitude":'+str(longitude)+',"latitude":'+str(latitude)+'}'+'}'
    return msg_cam

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
    
    # écriture du certificat dans un fichier
    cmd="echo "+certificat+ " > certificat_signe.crt"
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


def envoyer_data_scenario1(ip_passerelle,message,certificat_station):


    ## génération du hash
    message= bytes(message, 'utf-8')
    hash=hashlib.sha1(message).hexdigest()

    print("info: hash du message")
    print(hash)

    ## signature du hash avec la clé privée

#endef

if __name__ == '__main__' :

    fichier_paire_de_cles="keypair.pem"
    ip_autorite="192.168.3.17"
    
    generer_cles_rsa(fichier_paire_de_cles)
    generer_csr(fichier_paire_de_cles)
    csr_json=generer_json_csr("csr.pem")
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
    

    if scenario == '1':
        print("info: scénario authentification")
        envoyer_data_scenario1(ip_passerelle,"test1234","certificat_signe.crt")

    else : #scenario=2
        print("info: scénario confidentialité")
    #endef 

    #client.loop_forever()
    




   

    
    # while True :

    #     # génération stationType
    #     choix_stationType=random.randint(0,len(stationType_tab)-1)
    #     stationType=stationType_tab[choix_stationType]

    #     # génération vitesse
    #     if stationId == 2 :
    #         vitesse = random.randint(90,130)
    #     elif stationId == 3:
    #         vitesse = random.randint(0,90)
    #     else:
    #         vitesse = random.randint(0,130)
    #     #endif

    #     if vitesse < 90 :
    #         frequence_cam=1 # 1sec
    #     else:
    #         frequence_cam=0.100 #0,1
    #     #endif

    #     distance_parcourue=((vitesse/3.6)*frequence_cam)/1000
    #     longitude=longitude_base+(distance_parcourue*variation_degre_1km_longitude)
    #     latitude=latitude_base+(distance_parcourue*variation_degre_1km_latitude)

    #     timestamp=time.time()

    #     msg_cam = gen_msg_cam(stationId,stationType,longitude,latitude,vitesse,ip_server_mqtt,timestamp)

    #     # envoi d'un message denm à une fréquence de 1/10 de la fréquence d'envoi des msg CAM
    #     if cmpt_tour_boucle == 10:
    #         msg_denm = gen_msg_denm(stationId,stationType,longitude,latitude,vitesse,ip_server_mqtt,timestamp)
    #         print(msg_denm)
    #         cmpt_tour_boucle=0
    #     #endif

    #     print("envoi à une fréquence de "+str(frequence_cam))
    #     print(msg_cam)
    #     cmpt_tour_boucle+=1
    #     time.sleep(frequence_cam)
    #end
#endif

   
    
    



    
