#!/usr/bin/python3
import json, os, subprocess, threading, sys, datetime, time, random
import cryptography
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
# initialisation graine random
random.seed()

def generer_csr():

    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,

    )

    # Write our key to disk for safe keeping
    with open("key.pem", "wb") as f:
     f.write(key.private_bytes(
         encoding=serialization.Encoding.PEM,
         format=serialization.PrivateFormat.TraditionalOpenSSL,
         encryption_algorithm=serialization.NoEncryption(),
    ))

    cmd="openssl rsa -in key.pem -pubout -out pub.pem"   
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: clé publique extraite")

    print("info: génération clés OK")

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Reims"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Alexis et Marc"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"alexis-marc.fr"),
        ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"alexis-marc.fr"),
            x509.DNSName(u"www.alexis-marc.fr"),
            x509.DNSName(u"subdomain.alexis-marc.fr"),
        ]),
        critical=False,
    # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256())

    # Write our CSR out to disk.
    with open("crt.csr", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    
    print("info: CSR généré")
#endef

def generer_json_csr():

    #lecture binaire du certificat-recu
    f = open('crt.csr', "r")
    var=f.read()
    f.close()

    # récupération de l'ip de l'acteur demandant un certificat
    cmd="ip addr show | grep enp0s3 | grep inet | awk '{print $2}'"
    try:
        var2=subprocess.check_output(cmd, shell = True)
        var2=var2.decode()
        var2=str(var2)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    # création d'un dictionnaire
    dictionnaire = {"csr": var, "ip_demandeur_certificat":var2}

    # conversion du dictionnaire en json
    json_data=json.dumps(dictionnaire)

    # suppression du fichier csr
    cmd="rm crt.csr"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: fichier crt.csr supprimé")

    return json_data
    
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
    hostname = hostname.decode()
    hostname = str(hostname)

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


def gen_dictionnaire_cam(stationId,stationType,vitesse,heading,latitude,longitude,timestamp):
    dictionnaire_positionGPS = {"longitude":longitude,"latitude":latitude}
    dictionnaire = {"stationId":stationId,"stationType":stationType,"timestamp":timestamp,"vitesse":vitesse, "heading":heading, "positionGPS":dictionnaire_positionGPS }
    return dictionnaire
#endef

def gen_dictionnaire_denm(stationId,stationType,cause,sub_cause,latitude,longitude,timestamp):
    dictionnaire_positionGPS = {"longitude":longitude,"latitude":latitude}
    dictionnaire = {"stationId":stationId,"stationType":stationType,"timestamp":timestamp,"cause":cause, "sub-cause":sub_cause, "positionGPS":dictionnaire_positionGPS }
    return dictionnaire
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
    # print("info :données reçu")
    # print(donnees)
    certificat=donnees["certificatX509"]
    print("info: certificatx509 recu")
    #print(certificat)

    cle_publique_ac=str(donnees["cle_publique_ac"] )
    print("info: clé publique de l'autorité reçu")
    #print(cle_publique_ac)

    f = open('certificatx509.pem', "w")
    f.write(str(certificat))
    f.close()
    print("info: le certificatX509 de la station a été récupéré ")

    # écriture de la clé publique de l'AC
    f = open('cle_publique_ac.pem', "w")
    f.write(str(cle_publique_ac))
    f.close()
    print("info: la clé publique de l'AC a été récupérée")
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


def recuperer_cle_publique_certificat(certificatx509,cle_pub_certificat):
    cmd="openssl x509 -pubkey -noout -in "+certificatx509+" > "+cle_pub_certificat
    print(cmd)
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
#endef

def scenario1(stationId,stationType,vitesse,heading,latitude,longitude,timestamp,ip_passerelle):
    
    # construction du message CAM
    dictionnaire_data=gen_dictionnaire_cam(stationId,stationType,vitesse,heading,latitude,longitude,timestamp)
    
    # transformation du dictionnaire en json
    json_dictionnaire_data=json.dumps(dictionnaire_data)


    # hachage sha1 puis signature du json
    signer_hash_sha1_message(json_dictionnaire_data)


    # encodage de la signature binaire en base64 (nécessaire pour le transport)
    cmd="openssl base64 -in hash.bin -out hash-b64.txt"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    # lecture de la signature encodée en base64
    f= open("hash-b64.txt", "r")
    signature_base64=f.read()
    f.close()

    print("info: signature base64")
    print(signature_base64)

    # récupération du certificat
    f= open("certificatx509.pem", "r")
    certificat_station=f.read()
    f.close()


    dictionnaire={"data":dictionnaire_data,"signature_base64":signature_base64,"certificat_station":certificat_station}


    #conversion du dictionnaire en json
    json_data=json.dumps(dictionnaire)

    # construction requête bash
    topic=""
    if stationId == 1:
        topic="auto"
    elif stationId == 2:
        topic="moto"
    else:
        topic="camion"

    cmd="mosquitto_pub -h "+str(ip_passerelle)+" -q 1 "+"-u "+str(stationId)+" -t cam/"+str(topic)+" -m '"+str(json_data)+"'" 
    print(cmd)
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: message envoyé")


    # # suppression du fichier hash.bin
    # cmd="rm hash.bin"
    # try:
    #     os.system(cmd)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    # print("info: fichier hash.bin supprimé")

#endef


# def verif_signature():
#   #  COMMANDE FONCTIONNE
#     print("info: TEST VERIF ETAPE1") 
#     cmd="openssl dgst -sha1 -verify pub.pem -signature hash.bin message.txt"
#     try:
#         os.system(cmd)
#     except Exception as e:
#         sys.stderr.write(e.message+"\n")
#         exit(1)
# #endef

def signer_hash_sha1_message(message):

    # écriture de data (JSON)
    f = open('message.txt', "w")
    f.write(str(message))
    f.close()

    #signature avec la clé privée du véhicule
    cmd="openssl dgst -sha1 -sign key.pem -keyform PEM -out hash.bin message.txt"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)


    #suppresion du fichier tmp
    # cmd="rm message.txt"
    # try:
    #     os.system(cmd)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    # print("info: fichier message.txt supprimé")

#endef 

if __name__ == '__main__' :

    #definitions des variables
    ip_autorite="192.168.3.35"
    ip_passerelle="192.168.3.36"
    cle_pub_certificat="pubx509.pem"
    certificat="certificatx509.pem"
    
    #generer_cles_rsa(fichier_paire_de_cles)
    generer_csr()
    csr_json=generer_json_csr()
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
    
    frequence_cam=0
    longitude_base= 4.0333
    latitude_base=49.25
    heading=0
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
            
            scenario1(stationId,stationType,vitesse,heading,latitude,longitude,timestamp,ip_passerelle)
            exit(1)
            

            #  # envoi d'un message denm à une fréquence de 1/10 de la fréquence d'envoi des msg CAM
            # if cmpt_tour_boucle == 10:
            #     msg_denm = gen_msg_denm(stationId,stationType,longitude,latitude,vitesse,ip_passerelle,timestamp)
            #     print(msg_denm)
            #     cmpt_tour_boucle=0
            # #endif

            print("envoi à une fréquence de "+str(frequence_cam))
            #print(msg_cam)
            cmpt_tour_boucle+=1
            time.sleep(frequence_cam)

        else : #scenario=2
            print("info: scénario confidentialité")
        #endif



        #msg_cam = gen_msg_cam(stationId,stationType,longitude,latitude,vitesse,ip_server_mqtt,timestamp)

       
    #end
#endif

   
    
    



    
