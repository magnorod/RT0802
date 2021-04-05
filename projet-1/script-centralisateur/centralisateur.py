#!/usr/bin/python3
import json, time, threading, os
import paho.mqtt.client as mqtt

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

if __name__ == "__main__":
    
    client = mqtt.Client()
    client.on_message = on_message
    client.message_callback_add("denm/#", on_denm)
    client.connect("localhost", 1883, 60)

    client.subscribe("denm/passerelle")

    client.loop_forever()