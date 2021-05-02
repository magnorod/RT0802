#!/usr/bin/python3
import json, time, threading, os, sys, subprocess
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

    # récupération des 3 éléments
    data=donnees["data"]
    certificat=donnees["certificat_station"]
    signature=donnees["signature_base64"]

    print("info: data  recu:")
    print(data)

    print("info: certificat recu:")
    print(certificat)

    print("info: signature base64  recu:")
    
    print(signature)

    # écriture de data 
    f = open('data_recu.txt', "w")
    f.write(str(data))
    f.close()
    print("info: écriture de data dans un fichier tmp")
    
    # écriture du certif
    f = open('certif_recu.crt', "w")
    f.write(certificat)
    f.close()
    print("info: écriture du certificat dans un fichier tmp")
    
    # écriture de la signature encodée en base64 dans un fichier temporaire
    f = open('signature_base64_recu.txt', "w")
    f.write(signature)
    f.close()

    print("info: écriture de la signature dans un fichier tmp")
    
    # décoder la signature
    cmd="openssl base64 -d -in signature_base64_recu.txt -out signature_recu.sig"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: signature base64 décodée")

    ####### a) Vérifier le certificat de la station
    ##### Partie 1

    # récupération de la clé publique du certif recu
    cmd="openssl x509 -pubkey -out cle_publique_certif_recu.pem -in certif_recu.crt"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: récupération de la clé publique du certif reçu")

    # récupération de la clé publique de l'AC (située dans le certificat)
    cmd="openssl x509 -pubkey -out cle_publique_ac.pem -in certif_ac.crt"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: récupération de la clé publique de l'AC ")

   
    # extract hex of signature
    cmd="openssl x509 -in cle_publique_certif_recu.pem -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame | grep -v 'Signature Algorithm' | tr -d '[:space:]:'"
    try:
        var=subprocess.check_output(cmd, shell = True)
        var=var.decode()
        hex_signature=str(var)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: extract hex of signature")
    print(hex_signature)
    # create signature dump
    cmd="echo "+hex_signature+" | xxd -r -p > certif_recu_sig.bin"
    #echo 6c3fab065cd9f4d6a895fd5b73f31e47145e50157837ae3082b0a1090f58dee5363bdbb73924dd85112dc2471fb37cf19e21b05b7605f3ddefb7c9ad2f84d12d2ae3b3a9c2fa291e27d7cae1a7ae2e23301dce8071e600b60eba1751ef1af8ad4c87c772764e92562d271c5985dd2d9ced3a16beea7cb0bc213da38aa6fed8ceeb9e9b5fa63420057f478587aa5593c06d819ce9d653b02cb6181876275ad8818045850970fdcb774b25349266d7d664c349351dd3294f58cf98b939943c35c5170d6a19612c4775f1e2afa2a2605eab1cda91e8a08a7060ea5079cbbf2817f9ace1995623ac9ade6c90e4443e72cb1a0eee658d79698192213ad73d194130f6 | xxd -r -p > certif_recu_sig.bin
    print("\n")
    print(cmd)
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: create signature dump")

    # Déchiffrer la signature du certificat recu avec la clé publique de l'AC
    cmd="openssl rsautl -verify -inkey cle_publique_ac.pem -in certif_recu_sig.bin -pubin > certif_recu_sig_decrypted.bin"
    try:
        var=subprocess.check_output(cmd, shell = True)
        var=var.decode()
        decrypt_signature=str(var)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: decrypt signature")

    cmd="openssl asn1parse -inform der -in certif_recu_sig_decrypted.bin | awk '{ print $9 }' | cut -d':' -f2"
    try:
        var=subprocess.check_output(cmd, shell = True)
        var=var.decode()
        var=str(var)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: hash du certificat")
    print(var)
    
    ##### Partie2

    # récupération du body du certificat
    cmd="openssl asn1parse -in cle_publique_certif_recu.pem -strparse 4 -out cert_body.bin -noout"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: body du certificat récupéré")

    # calcul du hash du body
    
    cmd="openssl dgst -sha256 cert_body.bin"
    try:
        var=subprocess.check_output(cmd, shell = True)
        var=var.decode()
        var=str(var)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: hash calculé")
    print(var)


    # dechiffrer le condensat du certificat recu avec la clé publique de l'AC
    # cmd="openssl rsautl -verify -in certif_recu.crt -pubin cle_publique_ac.pem -out dedigest.txt"
    # try:
    #     var=subprocess.check_output(cmd, shell = True)
    #     var=var.decode()
    #     var=str(var)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    #openssl rsautl -decrypt -in certif_recu.crt -pubin cle_publique_ac.pem -out dedigest.txt
    #openssl x509 -in certif_recu.crt -text -noout -certopt
    #openssl x509 -in certif_recu.crt  -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame


    # # récupération de la clé publique du certificat reçu
    # cmd="openssl x509 -pubkey -noout -in certif_recu.crt"
    # try:
    #     var=subprocess.check_output(cmd, shell = True)
    #     var=var.decode()
    #     var2=str(var)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)

    # print("info: cle publique certif recu:")
    # print(var2)

    # # Comparaison des deux modulus
    # if var1 == var2 :
    #     print("info: le certificat recu a bien été signé par l'AC")
    # else:
    #     print("info: le certificat n'a pas été signé par l'AC")
    # #endif




    #Vérifier que l’empreinte signée a bien été signée avec le certificat envoyé

    # La passerelle déchiffre la signature reçu en utilisant la clé publique de la station qui est contenue dans le certificat reçu









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
    print("info :donnness")
    print(donnees)
    certificat=donnees["certificatX509"]
    print("info: certif recu")
    print(certificat)

    certif_ac=str(donnees["certif_ac"] )
    print("info: certif_ac")
    print(certif_ac)

    # écriture du certificat dans un fichier
    cmd="echo \""+certificat+"\" > certificatx509.crt"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    
    print("info: le certificatX509 de la station a été récupéré ")

    # écriture du certificat de l'AC
    f = open('certif_ac.crt', "w")
    f.write(str(certif_ac))
    f.close()
    print("info: le certificatX509 de l'AC a été récupéré")
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
