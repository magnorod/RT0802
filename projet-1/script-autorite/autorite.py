#!/usr/bin/python3
import json, os, subprocess, threading, sys, datetime, time, random,base64
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa




class Thread (threading.Thread):

    def __init__(self, csr, ip_demandeur_certificat):
        threading.Thread.__init__(self)
        self.csr = csr
        self.ip_demandeur_certificat = ip_demandeur_certificat
    #endef

    def run(self):
        
        print("\n##########EXECUTION D'UN THREAD##########")
        # print("thread : csr\n"+str(self.csr))
        # print("thread : ip_demandeur_certificat\n"+str(self.ip_demandeur_certificat))
        
        # créer un fichier temporaire contenant la clé publique recu
        f = open('csr-recu.pem', "w")
        f.write(str(self.csr))
        f.close()
        
        print("thread: fichier temporaire créé")

        # générer le certificat à partir de la clé publique reçu qui sera signée avec la clé privée de l'autorité
        signer_certificat()

        # envoyer le certif
        envoyer_certificat(self.ip_demandeur_certificat,"certificatX509","certificat-produit.pem")

    #endef

def envoyer_certificat(ip_desti,topic,certificat):

    #envoyer le certificat x509 qui a été généré à la cible 
    ip_desti=ip_desti[0:len(ip_desti)-4]


    # lecture du certificat généré pour la station
    f = open('certificat-produit.pem', "r")
    certificat=f.read()
    f.close()

    #extraction de la clé publique
    cmd="openssl rsa -in key.pem -pubout -out pub.pem"
    try:
        os.system(cmd)
    except Exception as e:
        sys.stderr.write(e.message+"\n")
        exit(1)
    print("info: clé publique extraite")

    # lecture du certificat généré pour la station
    f = open('pub.pem', "r")
    cle_publique_ac=f.read()
    f.close()

    # regroupement de l'ensemble des dictionnaires
    dictionnaire={"certificatX509":certificat,"cle_publique_ac":cle_publique_ac}

    #conversion du dictionnaire en json
    json_data=json.dumps(dictionnaire)

    cmd="mosquitto_pub -h "+str(ip_desti)+" -q 1 -u autorite -t config/"+str(topic)+" -m '"+str(json_data)+"'"
    try:
        os.system(cmd)
    except Exception as e:
        print(e.message)
    print("thread: certificat X509 envoyé au demandeur du CSR")

#endef

def on_message(client, userdata, msg):
    pass
#endef

def on_config(client, userdata, msg):
    donnees = json.loads(msg.payload.decode("utf-8"))
    csr_json=str(donnees["csr"] )
    ip_demandeur_certificat=str(donnees["ip_demandeur_certificat"] )

    # à la réception d'une csr lancement d'un thread pour s'occuper de la génération du certificat X509
    m = Thread(csr_json,ip_demandeur_certificat)
    m.start()

#endef

def signer_certificat():
    # signature du certificat
    cmd="openssl x509 -req -days 365 -in csr-recu.pem -signkey key.pem -out certificat-produit.pem"
    #print(cmd)
    try:
        os.system(cmd)
    except Exception as e:
        print(e.message)
    print("thread: certificat X509 signé par l'autorité")
#endef


def generer_certificat_autorite():

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

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"France"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Reims"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Alexis et Marc"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"alexis-marc.fr"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 365 days
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())
    # Write our certificate out to disk.
    with open("certificat-ac.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("info: certicat autosigné généré ")

#endef

if __name__ == '__main__' :

    generer_certificat_autorite()

    #attente d'une clé publique d'un véhicule ou de la station
    client = mqtt.Client()
    client.on_message = on_message
    client.message_callback_add("config/#", on_config)
    client.connect('127.0.0.1', 1883, 60)
    client.subscribe("config/csr")
    print("info: en attente de CSR")
    client.loop_forever()

#endif