#!/usr/bin/python3
import json, time, threading, os
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

def on_message(client, userdata, msg):
    pass

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

if __name__ == "__main__":
    client = mqtt.Client()
    client.on_message = on_message

    client.message_callback_add("cam/#", on_cam)
    client.message_callback_add("denm/#", on_denm)
    client.connect('127.0.0.1', 1883, 60)

    client.subscribe("cam/auto")
    client.subscribe("cam/moto")
    client.subscribe("cam/camion")

    client.subscribe("denm/auto")
    client.subscribe("denm/moto")
    client.subscribe("denm/camion")

    client.loop_forever()