#!/usr/bin/python3
import json, os, subprocess, threading, sys, datetime, time, random, base64
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# class MonThread (threading.Thread):
#     def __init__(self, donnees):
#         threading.Thread.__init__(self)
#         self.donnees = donnees
#     #endef

#     def run(self):
#         print("##########EXECUTION D'UN THREAD##########")
#         print("THREAD:donnees="+str(self.donnees))
#         #conversion du dictionnaire en json
#         donneesJson = json.dumps(self.donnees)
#         cmd1="mosquitto_pub -h 192.168.0.54 -q 1 -u passerelle -t denm/passerelle -m '"+str(donneesJson)+"'"
#         os.system(cmd1)
#         print("THREAD: cmd1="+str(cmd1))
#         print("THREAD:denm envoyé au centralisateur")
#     #endef

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

        
        # création du dictionnaire
        dictionnaire = {"peer_public_key":self.donnees}

        #conversion du dictionnaire en json
        donneesJson = json.dumps(dictionnaire)
        cmd="mosquitto_pub -h "+self.ip_desti+" -q 1 -u 1 -t "+self.topic+" -m '"+str(donneesJson)+"'"
        try:
            os.system(cmd)
        except Exception as e:
            sys.stderr.write(e.message+"\n")
            exit(1)

        print("thread(passerelle): cmd="+str(cmd))
        print("thread(passerelle): clé publique Diffie Hellman envoyée au centralisateur")

    #endef

#endclass

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




def on_dh(client, userdata, msg):

    # print("passerelle: demande d'échange Diffie-Hellman du centralisateur reçu")
    ip_desti="192.168.3.41"

    # Generate some parameters. These can be reused.
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Generate a private key for use in the exchange.
    private_key = parameters.generate_private_key()
    

    # envoyer la clé publique au centralisateur via un thread
    print("passerelle: thread créé")
    m = Thread_DH(private_key.public_key(),ip_desti,"dh/passerelle")
    print("passerelle: lancement du thread")
    m.start()

    # lire le contenu du msg
    # Au début de l'échange la passerelle reçoit une clé factice "start" qui ne sera pas utilisée lors de la dérivation
    
    donnees = json.loads(msg.payload.decode("utf-8"))
    print("donnees:"+str(donnees))
    peer_public_key=str(donnees["peer_public_key"])
   

    if peer_public_key != "start" : # la clé recu n'est pas la clé factice
        
        print("passerelle: Kc récupéré")
        shared_key = private_key.exchange(peer_public_key)

        # Perform key derivation
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            ).derive(shared_key)

        print("passerelle: K="+str(derived_key))
    #endif

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

    print("data:")
    print(data)

    data=str(data)
    print("dat(str):")
    print(data)

    #remplacement des simples quotes par des doubles quotes (cela pose problème au niveau de la vérif de la signature sinon)
    data=data.replace('\'', '\"')

    print("data après modif:")
    print(data)

    # écriture de data 
    f = open('data-recu.txt', "w")
    f.write(data)
    f.close()
    print("info: écriture de data dans un fichier tmp")
    
    # écriture du certif
    f = open('certif-recu.pem', "w")
    f.write(certificat)
    f.close()
    print("info: écriture du certificat dans un fichier tmp")


    #extraire clé publique du certif-recu
    cmd="openssl x509 -in certif-recu.pem -pubkey -out cle-publique-certif-recu.pem"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)


    print("info: signature base64 recu:")
    print(signature_base64)


    base64_bytes = signature_base64.encode("ascii")
    signature_binaire = base64.b64decode(base64_bytes)
    print("info: signature base64 binaire  décodée")


    #écriture de la signature binaire
    f = open('signature-recu.bin', "wb")
    f.write(signature_binaire)
    f.close()


    # lecture du  certificatx509 recu
    print("certificat_recu:")
    print(certificat)


    ###############VERIFICATION


    #lecture binaire du certificat-recu
    f = open('certif-recu.pem', "rb")
    certif_bytes=f.read()
    f.close()

    cert = x509.load_pem_x509_certificate(certif_bytes)
    print("info: chargement du certificat x509 recu")

    ####### a) Vérifier le hash de la signature du certificatx509 reçu 

    # # extract hex of signature
    cmd="openssl x509 -in certif-recu.pem -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame | grep -v 'Signature Algorithm' | tr -d '[:space:]:'"
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
    cmd="echo \""+hex_signature+"\" | xxd -r -p > signature-certif-recu.bin"
    print("\n")
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: create signature dump")

    # Déchiffrer la signature du certificat recu avec la clé publique de l'AC
    cmd="openssl rsautl -verify -inkey cle-publique-ac.pem -in signature-certif-recu.bin -pubin > signature-certif-recu-decrypt.bin"
    try:
        var=subprocess.check_output(cmd, shell = True)
        var=var.decode()
        decrypt_signature=str(var)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: decrypt signature")

    cmd="openssl asn1parse -inform der -in signature-certif-recu-decrypt.bin | grep HEX | awk '{print $9}' | cut -d':' -f2"
    try:
        var1=subprocess.check_output(cmd, shell = True)
        var1=var1.decode()
        hash_certificat=str(var1)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
   
    ##### Calculer le hash 
    # récupération du body du certificat
    cmd="openssl asn1parse -in certif-recu.pem -strparse 4 -out cert_body.bin -noout"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: body du certificat récupéré")

    # calcul du hash du body
    cmd="openssl dgst -sha256 cert_body.bin | awk {'print $2'}"
    try:
        var2=subprocess.check_output(cmd, shell = True)
        var2=var2.decode()
        hash_calcule=str(var2)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)

    # majuscule du hash calculé car les lettres sont en minuscules pour que ça match avec le hash du certificat-recu
    hash_calcule=hash_calcule.upper()

    print("info: hash du certificat")
    print(hash_certificat)
    print("info: hash calculé")
    print(hash_calcule)

    # comparaison des 2 hash
    if hash_calcule == hash_certificat :
        print("info: le certificatx509 reçu a bien été signé par l'AC")
        print("info: la clé publique du véhicule (comprise dans le certificatx509) a été certifié ")

        # Suppression des fichiers tmp
        cmd="rm cert_body.bin signature-certif-recu.bin signature-certif-recu-decrypt.bin "
        try:
            os.system(cmd)
        except Exception as e:
            sys.stderr.write(e.message+"\n")
            exit(1)

        ### Comme l'authenticité de la clé publique contenue dans le certificat reçu est avérée on passe à l'étape b)
        # verif
        print("info: vérification de la signature du hash de data")
        
        cmd="openssl dgst -sha1 -verify cle-publique-certif-recu.pem -signature signature-recu.bin data-recu.txt"
        try:
            var=subprocess.check_output(cmd, shell = True)
        except subprocess.CalledProcessError as err:
            print('ERROR:', err)
            exit(1)
        try:
            var=var.decode()
        except Exception as e:
            sys.stderr.write(e.message+"\n")
            exit(1)
        try:
            var=str(var)
            print("info: la station a bien utilisé sa clé privée pour signer le message. On est sûr que le message vient de la station correspondante à la clé publique contenue dans le certificat")
        except Exception as e:
            sys.stderr.write(e.message+"\n")
            exit(1)
    else:
        print("info: le certificatx509 reçu n'a pas été signé par l'AC")
    #endif

#endef


def init_dh(): # initie l'échange Diffie Hellman en envoyant la valeur "start" associée à la clé json "perr_public_key"
    
    donnees="start"
    ip_desti="127.0.0.1" #la passerelle s'envoi elle même un msg en faisant croire qu'il vient du centralisateur (pour démarrer l'échange DH)
    topic="dh/centralisateur"

    print("passerelle: lancement de l'échange Diffie Hellman")
    m = Thread_DH(donnees,ip_desti,topic)
    # crée un thread
    m.start()

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
    f = open('cle-publique-ac.pem', "w")
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
    client.message_callback_add("dh/#", on_dh)

    client.connect('127.0.0.1', 1883, 60)

    client.subscribe("config/certificatX509")
    client.subscribe("cam/auto")
    client.subscribe("cam/moto")
    client.subscribe("cam/camion")
    client.subscribe("denm/auto")
    client.subscribe("denm/moto")
    client.subscribe("denm/camion")
    client.subscribe("dh/centralisateur")

    client.loop_forever()
