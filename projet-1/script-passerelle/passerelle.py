#!/usr/bin/python3
import json, os, subprocess, threading, sys, datetime, time, random,base64
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
    signature_base64=donnees["signature_base64"]

    # print("info: data  recu:")
    # print(data)

    # print("info: certificat recu:")
    # print(certificat)


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


    # print("info: signature base64 recu:")
    # print(signature_base64)

    base64_bytes = signature_base64.encode("ascii")
    signature_binaire = base64.b64decode(base64_bytes)
    print("info: signature base64 binaire  décodée")


    # print("info: signature bianaire:")
    # print(signature_binaire)

    # écriture binaire de la signature
    f = open('signature_recu.sig', "wb")
    f.write(signature_binaire)
    f.close()

    print("info: écriture de la signature binaire dans le fichier signature_recu.sig ")


    
    ####### a) Vérifier le certificat de la station
    ##### Partie 1

    # # récupération de la clé publique du certif recu
    # cmd="openssl x509 -pubkey -out cle_publique_certif_recu.pem -in certif_recu.crt"
    # try:
    #     os.system(cmd)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    # print("info: récupération de la clé publique du certif reçu")

    # # extract hex of signature
    # cmd="openssl x509 -in cle_publique_certif_recu.pem -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame | grep -v 'Signature Algorithm' | tr -d '[:space:]:'"
    # try:
    #     var=subprocess.check_output(cmd, shell = True)
    #     var=var.decode()
    #     hex_signature=str(var)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    # print("info: extract hex of signature")
    # print(hex_signature)
    # # create signature dump
    # cmd="echo "+hex_signature+" | xxd -r -p > certif_recu_sig.bin"
    # print("\n")
    # print(cmd)
    # try:
    #     os.system(cmd)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    # print("info: create signature dump")

    # # Déchiffrer la signature du certificat recu avec la clé publique de l'AC
    # cmd="openssl rsautl -verify -inkey cle_publique_ac.pem -in certif_recu_sig.bin -pubin > certif_recu_sig_decrypted.bin"
    # try:
    #     var=subprocess.check_output(cmd, shell = True)
    #     var=var.decode()
    #     decrypt_signature=str(var)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    # print("info: decrypt signature")

    # cmd="openssl asn1parse -inform der -in certif_recu_sig_decrypted.bin | awk '{ print $9 }' | cut -d':' -f2"
    # try:
    #     var=subprocess.check_output(cmd, shell = True)
    #     var=var.decode()
    #     var=str(var)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    # print("info: hash du certificat")
    # print(var)
    
    # ##### Partie2

    # # récupération du body du certificat
    # cmd="openssl asn1parse -in cle_publique_certif_recu.pem -strparse 4 -out cert_body.bin -noout"
    # try:
    #     os.system(cmd)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    # print("info: body du certificat récupéré")

    # # calcul du hash du body
    
    # cmd="openssl dgst -sha256 cert_body.bin"
    # try:
    #     var=subprocess.check_output(cmd, shell = True)
    #     var=var.decode()
    #     var=str(var)
    # except Exception as e:
    #     sys.stderr.write(e.message+"\n")
    #     exit(1)
    # print("info: hash calculé")
    # print(var)


    # #dechiffrer le condensat du certificat recu avec la clé publique de l'AC
    # cmd="openssl rsautl -verify -in certif_recu.crt -pubin cle_publique_ac.pem -out dedigest.txt"
    # var=subprocess.check_output(cmd, shell = True)
    # var=var.decode()
    # var=str(var)

    # # openssl rsautl -decrypt -in certif_recu.crt -pubin cle_publique_ac.pem -out dedigest.txt
    # # openssl x509 -in certif_recu.crt -text -noout -certopt
    # # openssl x509 -in certif_recu.crt  -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame


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
    with open("csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    
    print("info: CSR généré")
#endef


def generer_json_csr():
    cmd="cat csr.pem"
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

    # création d'un dictionnaire
    dictionnaire = {"csr": var, "ip_demandeur_certificat":var2}

    #conversion du dictionnaire en json
    json_data=json.dumps(dictionnaire)

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

    print("info: CSR envoyée à l'autorité de certification")
    #endif
    
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

    f = open('certificatx509.crt', "w")
    f.write(str(certificat))
    f.close()
    print("info: le certificatX509 de la station a été récupéré ")

    # écriture de la clé publique de l'AC
    f = open('cle_publique_ac.pem', "w")
    f.write(str(cle_publique_ac))
    f.close()
    print("info: la clé publique de l'AC a été récupérée")
#endef


if __name__ == "__main__":

    ip_autorite="192.168.3.35"

    generer_csr()
    csr_json=generer_json_csr()
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

    client.loop_forever()
