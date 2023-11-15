from scapy.all import *
import psutil
from collections import defaultdict
import os
from threading import Thread
import pandas as pd

carry_weight = 3409
albion_name = "Albion-Online.exe"


CacheSize = 8192#CacheSize limit size of messages in cache

#ConfigGlobal replacement
Debug = False
PublicIngestBaseUrls = "http+pow:#pow.west.albion-online-data.com"
salesTax = 0.04

class MarketOrder:
  def __init__(self, ID, ItemID, GroupTypeId, LocationID, QualityLevel, EnchantmentLevel, Price, Amount, AuctionType, Expires):
    self.ID = ID               #int    `json:"Id"`
    self.ItemID = ItemID           #string `json:"ItemTypeId"`
    self.GroupTypeId = GroupTypeId      #string `json:"ItemGroupTypeId"`
    self.LocationID = LocationID       #int    `json:"LocationId"`
    self.QualityLevel = QualityLevel     #int    `json:"QualityLevel"`
    self.EnchantmentLevel = EnchantmentLevel #int    `json:"EnchantmentLevel"`
    self.Price = Price            #int    `json:"UnitPriceSilver"`
    self.Amount = Amount           #int    `json:"Amount"`
    self.AuctionType = AuctionType      #string `json:"AuctionType"`
    self.Expires = Expires          #string `json:"Expires"`

  def __str__(self):
	  return str([self.ID, self.ItemID, self.LocationID, self.QualityLevel, self.EnchantmentLevel, self.Price, self.Amount, self.AuctionType, self.Expires])

class marketHistoryInfo:
  def __init__(self, albionId, timescale, quality):
    self.albionId = albionId  #uint32
    self.timescale = timescale #lib.Timescale
    self.quality = quality   #uint8


class albionState:
  def __init__(self, LocationId, LocationString, CharacterId, CharacterName, GameServerIP, AODataServerID, marketHistoryIDLookup):
    self.LocationId = LocationId     #int
    self.LocationString = LocationString #string
    self.CharacterId = CharacterId    #lib.CharacterID
    self.CharacterName = CharacterName  #string
    self.GameServerIP = GameServerIP   #string
    self.AODataServerID = AODataServerID #int

    # A lot of information is sent out but not contained in the response when requesting marketHistory (e.g. ID)
    # This information is stored in marketHistoryInfo
    # This array acts as a type of cache for that info
    # The index is the message number (param255) % CacheSize
    self.marketHistoryIDLookup = marketHistoryIDLookup #[CacheSize]                    #marketHistoryInfo
    # TODO could this be improved?!


  def IsValidLocation(self):
    if self.LocationId < 0:
      if self.LocationId == -1:
        print("The players location has not yet been set. Please transition zones so the location can be identified.")
        #log.Error("The players location has not yet been set. Please transition zones so the location can be identified.")
        if not Debug:
          print("The players location has not yet been set. Please transition zones so the location can be identified.")
      else:
        print("The players location is not valid. Please transition zones so the location can be fixed.")
        if not Debug:
          print("The players location is not valid. Please transition zones so the location can be fixed.")
      return False
    return True
  

  def GetServerID(self):
    # default to 0
    serverID = 0
    # if we happen to have a server id stored in state, lets re-default to that
    if self.AODataServerID != 0:
      serverID = self.AODataServerID
    # we get packets from other than game servers, so determine if it's a game server
    # based on soruce ip and if its east/west servers
    isAlbionIP = False
    if os.path.commonprefix([self.GameServerIP, "5.188.125."]) == "5.188.125.":
      # west server class c ip range
      serverID = 1
      isAlbionIP = True
    elif os.path.commonprefix([self.GameServerIP, "5.45.187."]) == "5.45.187.":
      # east server class c ip range
      isAlbionIP = True
      serverID = 2
    # determine if the ConfigGlobal.PublicIngestBaseUrls contains either default east/west
    # data project server submission, if so, make sure it's set to the right hostname
    westUrl = "http+pow:#pow.west.albion-online-data.com"
    eastUrl = "http+pow:#pow.east.albion-online-data.com"
    if serverID == 1 and (not PublicIngestBaseUrls.count(eastUrl) > 0):
      # we're on west but using east hostname, change it
      while PublicIngestBaseUrls.count(eastUrl) > 0:
        PublicIngestBaseUrls[PublicIngestBaseUrls.index(eastUrl)] == westUrl
    elif serverID == 2 and (not PublicIngestBaseUrls.count(westUrl) > 0):
      # we're on east but using west hostname, change it
      while PublicIngestBaseUrls.count(westUrl) > 0:
        PublicIngestBaseUrls[PublicIngestBaseUrls.index(westUrl)] == eastUrl
    # if this was a known albion online server ip, then let's log it
    #if isAlbionIP:
    #  print("Using %v for PublicIngestBaseUrls", ConfigGlobal.PublicIngestBaseUrls)
    #  print("Returning Server ID %v (ip src: %v)", serverID, self.GameServerIP)
    return serverID

def process_packet(packet):
    global pid2traffic
    try:
        # get the packet source & destination IP addresses and ports
        packet_connection = (packet.sport, packet.dport)
    except (AttributeError, IndexError):
        # sometimes the packet does not have TCP/UDP layers, we just ignore these packets
        pass
    else:
        # get the PID responsible for this connection from our `connection2pid` global dictionary
        packet_pid #= connection2pid.get(packet_connection)
        #if packet_pid:
        #    if packet.src in all_macs:
        #        # the source MAC address of the packet is our MAC address
        #        # so it's an outgoing packet, meaning it's upload
        #        pid2traffic[packet_pid][0] += len(packet)
        #    else:
        #        # incoming packet, download
        #        pid2traffic[packet_pid][1] += len(packet)


if __name__ == "__main__":
    # start the printing thread
    #printing_thread = Thread(target=print_stats)
    #printing_thread.start()
    # start the get_connections() function to update the current connections of this machine
    #connections_thread = Thread(target=get_connections)
    #connections_thread.start()

    # start sniffing
    print("Started sniffing")
    #p = sr1(IP(dst="localhost")/ICMP()/"XXXXXXXXXXXX")
    #p
    #p.show()
    #for x in get_if_list():
    #  print(x)
    ls()
    #  sniff(iface=x, prn=lambda x: x.show(), store=False)
    # setting the global variable to False to exit the program
    is_program_running = False   