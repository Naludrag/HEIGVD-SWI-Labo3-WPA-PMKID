#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein et Yann Lederrey"
__modified__ = "Robin Müller et Stéphane Teixeira Carvalho"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from scapy.layers.dot11 import *

from pbkdf2 import *
import hmac, hashlib

"""
To make this script work, scappy 2.4.3 needs to be installed with the command : pip install scapy==2.4.3
We decided to use this version because it offers a clean way to go through packets that were removed 
in the latest versions.
"""

def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


def getAssociationRequestInfo(packets):
    """
    Will get all the useful values from an association request packet
    :param packets: the list of packets to analyse
    :return: the ssid of the AP, the MAC of the AP and the Client
    """
    # Search for an association request in the list of packets
    assocRequests = list(filter(lambda pkt: pkt.haslayer(Dot11AssoReq), packets))
    # Exception if we do not find any association request
    if len(assocRequests) == 0:
        raise Exception("Cannot find association request")

    # Retrieve info from the first association request found
    pkt = assocRequests[0]
    # info will give the ssid of the AP
    ssid = pkt.info.decode('ascii')
    # addr1 is where the MAC of the AP is stored in the first association request in our case
    APmac = a2b_hex(pkt.addr1.replace(':', ''))
    # addr2 is where the MAC of the client is stored in the first association request in our case
    Clientmac = a2b_hex(pkt.addr2.replace(':', ''))
    print(pkt)
    return ssid, APmac, Clientmac

def main():
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("PMKID_handshake.pcap")

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    passPhrase = "admin123"

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    ssid, APmac, Clientmac = getAssociationRequestInfo(wpa)

    print("\n\nValues used to derivate keys")
    print("============================")
    print("Passphrase: ", passPhrase, "\n")
    print("SSID: ", ssid, "\n")
    print("AP Mac: ", b2a_hex(APmac), "\n")
    print("CLient Mac: ", b2a_hex(Clientmac), "\n")

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    ssid = str.encode(ssid)
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

if __name__ == "__main__":
    main()
