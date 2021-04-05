# TP1 Commandes de bases Openssl

## Exercice 1: Découverte d'openssl
### 1) Quels sont les commandes/outils contenu(e)s dans openssl ?

```asn1parse
    Traitement d'une séquence ASN.1.

ca
    Gestion Certificate Authority (CA).

ciphers
    Détermination de la description de la suite de chiffrement.

crl
    Gestion Certificate Revocation List (CRL).

crl2pkcs7
    Conversion CRL vers PKCS#7.

dgst
    Calcul signature message (MD5).

dh
    Gestion des paramètres Diffie-Hellman. Obsolète par dhparam.

dsa
    Gestion données DSA.

dsaparam
    Génération paramètres DSA.

enc
    Chiffrement.

errstr
    Conversion numéro d'erreur vers descriptif texte (String).

dhparam
    Génération et gestion de paramètres Diffie-Hellman.

gendh
    Génération de paramètres Diffie-Hellman. Obsolète par dhparam.

gendsa
    Génération de paramètres DSA.

genrsa
    Génération de paramètres RSA.

passwd
    Génération de mots de passe hashés.

pkcs7
    Gestion données PKCS#7.

rand
    Génère octets pseudo-aléatoires.

req
    Gestion X.509 Certificate Signing Request (CSR).

rsa
    Gestion données RSA.
rsautl
    Utilitaire RSA pour signature, vérification, chiffrement, et déchiffrement.

s_client
    Ceci fournit un client SSL/TLS générique qui sait établir une connexion transparente avec un serveur distant parlant SSL/TLS. Étant seulement prévu pour des propos de test, il n'offre qu'une interface fonctionnelle rudimentaire tout en utilisant en interne la quasi-totalité des fonctionnalités de la librairie ssl d'OpenSSL.

s_server
    Ceci fournit un client SSL/TLS générique qui accepte des connexions transparentes provenant de clients qui parlent SSL/TLS. Étant seulement prévu pour des propos de test, il n'offre qu'une interface fonctionnelle rudimentaire tout en utilisant en interne la quasi-totalité des fonctionnalités de la librairie ssl d'OpenSSL. Il fournit à la fois son propre protocole orienté commandes en ligne pour le test de fonctions SSL et une facilité de réponse simple HTTP pour émuler un serveur internet qui gère SSL/TLS.

s_time
    Horlogeur de connections SSL.

sess_id
    Gestion des données de session SSL.

smime
    Traitement mails S/MIME.

speed
    Mesure la vitesse de l'algorithme.

verify
    Vérification du certificat X.509.

version
    Information sur la version d'OpenSSL.

x509
    Gestion de données pour le certificat X.509. 
```

### 2) Déterminer la version de votre openssl avec la commande openssl version -a


```
marc@hp-tour:~$ openssl version -a
OpenSSL 1.1.1f  31 Mar 2020
built on: Mon Mar 22 11:37:17 2021 UTC
platform: debian-amd64
options:  bn(64,64) rc4(16x,int) des(int) blowfish(ptr) 
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -Wa,--noexecstack -g -O2 -fdebug-prefix-map=/build/openssl-Juj39H/openssl-1.1.1f=. -fstack-protector-strong -Wformat -Werror=format-security -DOPENSSL_TLS_SECURITY_LEVEL=2 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2
OPENSSLDIR: "/usr/lib/ssl"
ENGINESDIR: "/usr/lib/x86_64-linux-gnu/engines-1.1"
Seeding source: os-specific
```

### 3) Qu'obtient-on en tapant la commande openssl ciphers -v ?


```
marc@hp-tour:~$ openssl ciphers -v
TLS_AES_256_GCM_SHA384  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(256) Mac=AEAD
TLS_CHACHA20_POLY1305_SHA256 TLSv1.3 Kx=any      Au=any  Enc=CHACHA20/POLY1305(256) Mac=AEAD
TLS_AES_128_GCM_SHA256  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(128) Mac=AEAD
ECDHE-ECDSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(256) Mac=AEAD
ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(256) Mac=AEAD
DHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=DH       Au=RSA  Enc=AESGCM(256) Mac=AEAD
ECDHE-ECDSA-CHACHA20-POLY1305 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=CHACHA20/POLY1305(256) Mac=AEAD
ECDHE-RSA-CHACHA20-POLY1305 TLSv1.2 Kx=ECDH     Au=RSA  Enc=CHACHA20/POLY1305(256) Mac=AEAD
DHE-RSA-CHACHA20-POLY1305 TLSv1.2 Kx=DH       Au=RSA  Enc=CHACHA20/POLY1305(256) Mac=AEAD
ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(128) Mac=AEAD
ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(128) Mac=AEAD
DHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=DH       Au=RSA  Enc=AESGCM(128) Mac=AEAD
ECDHE-ECDSA-AES256-SHA384 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(256)  Mac=SHA384
ECDHE-RSA-AES256-SHA384 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA384
DHE-RSA-AES256-SHA256   TLSv1.2 Kx=DH       Au=RSA  Enc=AES(256)  Mac=SHA256
ECDHE-ECDSA-AES128-SHA256 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(128)  Mac=SHA256
ECDHE-RSA-AES128-SHA256 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AES(128)  Mac=SHA256
DHE-RSA-AES128-SHA256   TLSv1.2 Kx=DH       Au=RSA  Enc=AES(128)  Mac=SHA256
ECDHE-ECDSA-AES256-SHA  TLSv1 Kx=ECDH     Au=ECDSA Enc=AES(256)  Mac=SHA1
ECDHE-RSA-AES256-SHA    TLSv1 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA1
DHE-RSA-AES256-SHA      SSLv3 Kx=DH       Au=RSA  Enc=AES(256)  Mac=SHA1
ECDHE-ECDSA-AES128-SHA  TLSv1 Kx=ECDH     Au=ECDSA Enc=AES(128)  Mac=SHA1
ECDHE-RSA-AES128-SHA    TLSv1 Kx=ECDH     Au=RSA  Enc=AES(128)  Mac=SHA1
DHE-RSA-AES128-SHA      SSLv3 Kx=DH       Au=RSA  Enc=AES(128)  Mac=SHA1
RSA-PSK-AES256-GCM-SHA384 TLSv1.2 Kx=RSAPSK   Au=RSA  Enc=AESGCM(256) Mac=AEAD
DHE-PSK-AES256-GCM-SHA384 TLSv1.2 Kx=DHEPSK   Au=PSK  Enc=AESGCM(256) Mac=AEAD
RSA-PSK-CHACHA20-POLY1305 TLSv1.2 Kx=RSAPSK   Au=RSA  Enc=CHACHA20/POLY1305(256) Mac=AEAD
DHE-PSK-CHACHA20-POLY1305 TLSv1.2 Kx=DHEPSK   Au=PSK  Enc=CHACHA20/POLY1305(256) Mac=AEAD
ECDHE-PSK-CHACHA20-POLY1305 TLSv1.2 Kx=ECDHEPSK Au=PSK  Enc=CHACHA20/POLY1305(256) Mac=AEAD
AES256-GCM-SHA384       TLSv1.2 Kx=RSA      Au=RSA  Enc=AESGCM(256) Mac=AEAD
PSK-AES256-GCM-SHA384   TLSv1.2 Kx=PSK      Au=PSK  Enc=AESGCM(256) Mac=AEAD
PSK-CHACHA20-POLY1305   TLSv1.2 Kx=PSK      Au=PSK  Enc=CHACHA20/POLY1305(256) Mac=AEAD
RSA-PSK-AES128-GCM-SHA256 TLSv1.2 Kx=RSAPSK   Au=RSA  Enc=AESGCM(128) Mac=AEAD
DHE-PSK-AES128-GCM-SHA256 TLSv1.2 Kx=DHEPSK   Au=PSK  Enc=AESGCM(128) Mac=AEAD
AES128-GCM-SHA256       TLSv1.2 Kx=RSA      Au=RSA  Enc=AESGCM(128) Mac=AEAD
PSK-AES128-GCM-SHA256   TLSv1.2 Kx=PSK      Au=PSK  Enc=AESGCM(128) Mac=AEAD
AES256-SHA256           TLSv1.2 Kx=RSA      Au=RSA  Enc=AES(256)  Mac=SHA256
AES128-SHA256           TLSv1.2 Kx=RSA      Au=RSA  Enc=AES(128)  Mac=SHA256
ECDHE-PSK-AES256-CBC-SHA384 TLSv1 Kx=ECDHEPSK Au=PSK  Enc=AES(256)  Mac=SHA384
ECDHE-PSK-AES256-CBC-SHA TLSv1 Kx=ECDHEPSK Au=PSK  Enc=AES(256)  Mac=SHA1
SRP-RSA-AES-256-CBC-SHA SSLv3 Kx=SRP      Au=RSA  Enc=AES(256)  Mac=SHA1
SRP-AES-256-CBC-SHA     SSLv3 Kx=SRP      Au=SRP  Enc=AES(256)  Mac=SHA1
RSA-PSK-AES256-CBC-SHA384 TLSv1 Kx=RSAPSK   Au=RSA  Enc=AES(256)  Mac=SHA384
DHE-PSK-AES256-CBC-SHA384 TLSv1 Kx=DHEPSK   Au=PSK  Enc=AES(256)  Mac=SHA384
RSA-PSK-AES256-CBC-SHA  SSLv3 Kx=RSAPSK   Au=RSA  Enc=AES(256)  Mac=SHA1
DHE-PSK-AES256-CBC-SHA  SSLv3 Kx=DHEPSK   Au=PSK  Enc=AES(256)  Mac=SHA1
AES256-SHA              SSLv3 Kx=RSA      Au=RSA  Enc=AES(256)  Mac=SHA1
PSK-AES256-CBC-SHA384   TLSv1 Kx=PSK      Au=PSK  Enc=AES(256)  Mac=SHA384
PSK-AES256-CBC-SHA      SSLv3 Kx=PSK      Au=PSK  Enc=AES(256)  Mac=SHA1
ECDHE-PSK-AES128-CBC-SHA256 TLSv1 Kx=ECDHEPSK Au=PSK  Enc=AES(128)  Mac=SHA256
ECDHE-PSK-AES128-CBC-SHA TLSv1 Kx=ECDHEPSK Au=PSK  Enc=AES(128)  Mac=SHA1
SRP-RSA-AES-128-CBC-SHA SSLv3 Kx=SRP      Au=RSA  Enc=AES(128)  Mac=SHA1
SRP-AES-128-CBC-SHA     SSLv3 Kx=SRP      Au=SRP  Enc=AES(128)  Mac=SHA1
RSA-PSK-AES128-CBC-SHA256 TLSv1 Kx=RSAPSK   Au=RSA  Enc=AES(128)  Mac=SHA256
DHE-PSK-AES128-CBC-SHA256 TLSv1 Kx=DHEPSK   Au=PSK  Enc=AES(128)  Mac=SHA256
RSA-PSK-AES128-CBC-SHA  SSLv3 Kx=RSAPSK   Au=RSA  Enc=AES(128)  Mac=SHA1
DHE-PSK-AES128-CBC-SHA  SSLv3 Kx=DHEPSK   Au=PSK  Enc=AES(128)  Mac=SHA1
AES128-SHA              SSLv3 Kx=RSA      Au=RSA  Enc=AES(128)  Mac=SHA1
PSK-AES128-CBC-SHA256   TLSv1 Kx=PSK      Au=PSK  Enc=AES(128)  Mac=SHA256
PSK-AES128-CBC-SHA      SSLv3 Kx=PSK      Au=PSK  Enc=AES(128)  Mac=SHA1
```

affiche les algo de chiffrement qui prennent en charge SSL/TLS

### 4) Comment lister les commandes qui utilisent uniquement l'algorithme de chiffrement 3DES ?

```
marc@hp-tour:~$ openssl list -cipher-commands |grep des3
des-ede3-ofb      des-ofb           des3              desx 
```

## Exercice 2 : Chiffrement / Déchiffrement

### 1)

```marc@hp-tour:~$ echo "Bonjour" > test.txt
marc@hp-tour:~$ cat test.txt
Bonjour
marc@hp-tour:~$ openssl enc -e -des-cbc -in test.txt -out test-chiffr.txt
enter des-cbc encryption password:
Verifying - enter des-cbc encryption password:
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
```

### 2)

```
marc@hp-tour:~$ cat test-chiffr.txt
Salted__o��u#}�$���P���k��j�
```
On remarque un sel. Un sel permet de renforcer un algorithme de chiffrement.

### 3)

```
marc@hp-tour:~$ openssl enc -d -des-cbc -in test-chiffr.txt -out test-dechiffr.txt
enter des-cbc decryption password:
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
marc@hp-tour:~$ cat test-dechiffr.txt 
Bonjour
```
### 4) Est-il possible de chiffrer avec un AES-128 et déchiffrer avec un AES-192 ?

Non pas possible

### 5) 



```marc@hp-tour:~$ openssl enc  -des-cbc -in test2.txt  -p -out test2-chiffr.txt
enter des-cbc encryption password:
Verifying - enter des-cbc encryption password:
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
salt=809F5A2E23BCF590
key=187280FA4A1C7B97
iv =F597333EC9ACC2DD
```
l'option -p affiche sel/iv/key

sel= généré via la saisie du mot de passe

iv =initialization vector

key=clé générée en utilisant le sel

### 6) 

```marc@hp-tour:~$ openssl enc -e -des-cbc -in test2.txt -p -out test3-chiffr.txt
enter des-cbc encryption password:
Verifying - enter des-cbc encryption password:
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
salt=4DF6D1975E4482FF
key=7C03A2677882AC82
iv =E6C1B42653CE0962
```
Non les informations ne sont pas identiques

### 7)

```marc@hp-tour:~$ openssl enc  -des-cbc -in test2.txt  -p -out test3-chiffr.txt -nosalt
enter des-cbc encryption password:
Verifying - enter des-cbc encryption password:
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
key=03AC674216F3E15C
iv =761EE1A5E255F067

marc@hp-tour:~$ openssl enc  -des-cbc -in test2.txt  -p -out test3-chiffr.txt -nosalt
enter des-cbc encryption password:
Verifying - enter des-cbc encryption password:
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
key=03AC674216F3E15C
iv =761EE1A5E255F067
```

on trouve la même clé pour les 2 commandes car on n'utilise pas de sel pour la génération de celle-ci

## Exercice 3 Premiers pas sur RSA

### 1) 

```
marc@hp-tour:~/tp802$ openssl genrsa -out signature.pem 1024
Generating RSA private key, 1024 bit long modulus (2 primes)
....+++++
...+++++
e is 65537 (0x010001)
marc@hp-tour:~/tp802$ cat signature.pem 
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDVJbRBz/6xMlbwcPyaQkgmBJLttjuCowr0xqjuBhJiGSJqptI0
mMj4lxVP8fVvinAM5qmJKGWYulDShnkXng7QDrcCqB+JwKF4UuM40W99WkPoC/zV
G0Wt1KWbAZA5tFuZYnZiJn3voa+R/P5RtzSywQSL7eXnk7WPC9jP1We6jQIDAQAB
AoGALGC+SBmTMLeHbGZJ4aA9P1UidkXD3C4wIMif8XboKu6KwOPczkClT0S9ljiN
XlzXeYgo8jqr9IGORFblLWqmMIAqRL8XTb+RE/OG8m/yR5IQtHOgnLCmXd7FC93m
HaJYvNmXd90erd1kEAreUH7yvaIk9sQPuXJWb6rUMBjL/O0CQQDqcPGJQNdHAkp4
mM5qwxSXJqEQMfmjjWpPakSsImMa0ODhI/xgzXB1YdMJjKCUFfVCk7ur4XlEE5kx
f2EyUmwfAkEA6L95UJ/Un5RYEsiH4Jc3xQEM5FIVeSA2EN/1ABVjBUNeAzOQXlKK
Knw1uyJhZWZcSwEcCO+PAtgf5HIa2UPD0wJARqZ+w6QcvDN+idVS722WuO5VP3Iw
Dw/A5+nYhB9gymYEPxT/K5T9vQIb/Ra6FaaAYO3wcp3iU5esZPREMEwSdQJAX0bi
loqXM6w6UZYdaWb9wXuol16yw57YAxhq5tnaazEkrxLQqowHW1T1eeGdFTFN3rZZ
j57hYDyw8Yd0TjRbWQJBAK5w1aviwtoqIH9BAC4Sn/ePRa1SMUG5IwkDi5NvkcYC
0PSm2fbRSHNcKC8Miijxg/VyHKlX6RzauDHE/g1hC/w=
-----END RSA PRIVATE KEY-----
```

### 2)



```
marc@hp-tour:~/tp802$ openssl rsa -in signature.pem -text -noout
RSA Private-Key: (1024 bit, 2 primes)
modulus:
    00:d5:25:b4:41:cf:fe:b1:32:56:f0:70:fc:9a:42:
    48:26:04:92:ed:b6:3b:82:a3:0a:f4:c6:a8:ee:06:
    12:62:19:22:6a:a6:d2:34:98:c8:f8:97:15:4f:f1:
    f5:6f:8a:70:0c:e6:a9:89:28:65:98:ba:50:d2:86:
    79:17:9e:0e:d0:0e:b7:02:a8:1f:89:c0:a1:78:52:
    e3:38:d1:6f:7d:5a:43:e8:0b:fc:d5:1b:45:ad:d4:
    a5:9b:01:90:39:b4:5b:99:62:76:62:26:7d:ef:a1:
    af:91:fc:fe:51:b7:34:b2:c1:04:8b:ed:e5:e7:93:
    b5:8f:0b:d8:cf:d5:67:ba:8d
publicExponent: 65537 (0x10001)
privateExponent:
    2c:60:be:48:19:93:30:b7:87:6c:66:49:e1:a0:3d:
    3f:55:22:76:45:c3:dc:2e:30:20:c8:9f:f1:76:e8:
    2a:ee:8a:c0:e3:dc:ce:40:a5:4f:44:bd:96:38:8d:
    5e:5c:d7:79:88:28:f2:3a:ab:f4:81:8e:44:56:e5:
    2d:6a:a6:30:80:2a:44:bf:17:4d:bf:91:13:f3:86:
    f2:6f:f2:47:92:10:b4:73:a0:9c:b0:a6:5d:de:c5:
    0b:dd:e6:1d:a2:58:bc:d9:97:77:dd:1e:ad:dd:64:
    10:0a:de:50:7e:f2:bd:a2:24:f6:c4:0f:b9:72:56:
    6f:aa:d4:30:18:cb:fc:ed
prime1:
    00:ea:70:f1:89:40:d7:47:02:4a:78:98:ce:6a:c3:
    14:97:26:a1:10:31:f9:a3:8d:6a:4f:6a:44:ac:22:
    63:1a:d0:e0:e1:23:fc:60:cd:70:75:61:d3:09:8c:
    a0:94:15:f5:42:93:bb:ab:e1:79:44:13:99:31:7f:
    61:32:52:6c:1f
prime2:
    00:e8:bf:79:50:9f:d4:9f:94:58:12:c8:87:e0:97:
    37:c5:01:0c:e4:52:15:79:20:36:10:df:f5:00:15:
    63:05:43:5e:03:33:90:5e:52:8a:2a:7c:35:bb:22:
    61:65:66:5c:4b:01:1c:08:ef:8f:02:d8:1f:e4:72:
    1a:d9:43:c3:d3
exponent1:
    46:a6:7e:c3:a4:1c:bc:33:7e:89:d5:52:ef:6d:96:
    b8:ee:55:3f:72:30:0f:0f:c0:e7:e9:d8:84:1f:60:
    ca:66:04:3f:14:ff:2b:94:fd:bd:02:1b:fd:16:ba:
    15:a6:80:60:ed:f0:72:9d:e2:53:97:ac:64:f4:44:
    30:4c:12:75
exponent2:
    5f:46:e2:96:8a:97:33:ac:3a:51:96:1d:69:66:fd:
    c1:7b:a8:97:5e:b2:c3:9e:d8:03:18:6a:e6:d9:da:
    6b:31:24:af:12:d0:aa:8c:07:5b:54:f5:79:e1:9d:
    15:31:4d:de:b6:59:8f:9e:e1:60:3c:b0:f1:87:74:
    4e:34:5b:59
coefficient:
    00:ae:70:d5:ab:e2:c2:da:2a:20:7f:41:00:2e:12:
    9f:f7:8f:45:ad:52:31:41:b9:23:09:03:8b:93:6f:
    91:c6:02:d0:f4:a6:d9:f6:d1:48:73:5c:28:2f:0c:
    8a:28:f1:83:f5:72:1c:a9:57:e9:1c:da:b8:31:c4:
    fe:0d:61:0b:fc
```
modulus correspond au modulo, exposants= la puissance, prime = nb premier


l'exposant publique vaut 65537 dans le but d ’accélérer les calculs informatiques. En effet, 65537 = (2**16) + 1, c’est-`a-dire que sa représentation binaire n’a que deux uns et nécessite peu de multiplications lors de son exponentiation. C’est la raison pour laquelle l’exposant public est 65537.
