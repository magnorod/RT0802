#!/usr/bin/python3
import binascii
"""
ord(c)
Renvoie le nombre entier représentant le code Unicode du caractère représenté par la chaîne donnée.
Par exemple, ord('a') renvoie le nombre entier 97 et ord('€') (symbole euro) renvoie 8364. Il s'agit de l'inverse de chr().

chr(c)
Renvoie la chaîne représentant un caractère dont le code de caractère Unicode est le nombre entier i.
Par exemple, chr(97) renvoie la chaîne de caractères 'a', tandis que chr(8364) renvoie '€'. Il s'agit de l'inverse de ord().
L'intervalle valide pour cet argument est de 0 à 1114111 (0x10FFFF en base 16). Une exception ValueError est levée si i est en dehors de l'intervalle.

zip(m,c)
Construit un itérateur agrégeant les éléments de tous les itérables.

"""

def xor_chiffr(message,cle):
    message_chiffre=[]
    for a,b in zip(message,cle):
        """
        print("a="+str(a))
        print("b="+str(b))
        print("ord(a):"+str(ord(a)))
        """
        message_chiffre.append(chr(ord(a)^ord(b)))
    #endfor
    print("message_chiffre="+str(message_chiffre) )    
    message_chiffre2=''.join(message_chiffre)
    print("message_chiffre (imprimable)="+str(message_chiffre2))

    return message_chiffre
#endef

def xor_dechiffr(message_chiffre,cle):

    message_chiffre=''.join(message_chiffre)

    message_dechiffre=[]
    for a,b in zip(message_chiffre,cle):
        """
        print("a="+str(a))
        print("b="+str(b))
        print("ord(a):"+str(ord(a)))
        """
        message_dechiffre.append(chr(ord(a)^ord(b)))
    #endfor
    print("message_dechiffre="+str(message_dechiffre) )    
    message_dechiffre2=''.join(message_dechiffre)
    print("message_dechiffre (imprimable)="+str(message_dechiffre))

#endef

"""
def xor_decrypt(message_chiffre):

    # génération d'une clé de 2048 bits donc
    # 256 caractères ASCII dans la clé sachant q'un caractères ASCII a 128 possibilités 

    for i in range (00,128**256,1):

        
        message_chiffre=''.join(message_chiffre)
        debut="0000000"
        fin="1111111"
        
        cle=bin(i)
        cle_t=chr(cle)

        print("cle:"+str(cle)+" i:"+str(i))

        ### à terminer

        #endif



    ## écriture de la clé dans un fichier

    ## lecture du fichier et comparaison avec une wordlist en comptant le nb d'occurences
    ## la ligne qui aura match le plus de fois avec la wordlist correspondra au message de base


    #endfor

"""

if __name__=="__main__":

    # Chiffrement
    message="petit test"
    # clé de 2048 bits = 256 caractères
    cle="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum pharetra nunc velit, at imperdiet ipsum consectetur et. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse vulputate purus mauris, eu venenatis lectus bibendum id a111111"
    print("message de départ:"+message)
    message_chiffre=xor_chiffr(message,cle)

    # Déchiffrement
    xor_dechiffr(message_chiffre,cle)

    #xor_decrypt(message_chiffre)

#endif
