FROM alpine:latest

RUN apk update \
&& apk add mosquitto mosquitto-clients python3 py3-pip openrc --no-cache \
&& pip install paho-mqtt 