"""
run this script as root.
the script will listen for ARP packets and will toggle the yeelight bulb when it finds them.
note that if your yeelight bulb is already initialized it will not reveal it's token. you need to find it yourself
and give it as an argument to yeetoggle.toggle() (see comment below)
"""
from scapy.all import *
import yeetoggle


AMAZON_DASH_MAC_ADDRESS = '00:00:00:00:00:00'  # TODO: put your's here


def arp_sniff_and_replace(pkt):
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 1:
                if pkt[ARP].hwsrc == AMAZON_DASH_MAC_ADDRESS: # Bounty
                    print("button pushed -> toggle yeelight")
                    yeetoggle.toggle()  # if you have the token use: yeetoggle.toggle(token)
                else:
                    # print("ARP Probe from unknown device: " + pkt[ARP].hwsrc)
                    pass


if __name__ == "__main__":
    sniff(prn=arp_sniff_and_replace, filter="arp", store=0, count=0)