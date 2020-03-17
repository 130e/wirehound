#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import dpkt
import socket
import datetime
import json
import networkx
import pyvis
import math


# In[ ]:


class Packet(object):

    def __init__(self, timestamp, ip_datagram):
        self.sip = ip_datagram.src #sip and dip is saved in HEX format
        self.dip = ip_datagram.dst
        self.proto = ip_datagram.p
        self.protoName = ip_datagram.get_proto(ip_datagram.p).__name__
        self.length = ip_datagram.len
        self.timestamp = timestamp
        
        self.__isNetworkLayer = True
        self.__isTransportLayer = False
        self.__isApplicationLayer = False
        self.__isICMPQuery = False
        self.__isTCP = False
        
        
        if self.proto in [1]: #ICMP
            if(ip_datagram.data.type in [0,8,13,14,15,16,17,18,30]):
                self.__isICMPQuery = True
                self.xInfo =                     (ip_datagram.data.type, ip_datagram.data.code, ip_datagram.data.data.id)
            else:
                self.xInfo =                     (ip_datagram.data.type, ip_datagram.data.code, None)
            pass
        elif self.proto in [6,17]: #TCP/UDP    
            transport_segment = ip_datagram.data
            self.__isTransportLayer = True
            self.sport = transport_segment.sport
            self.dport = transport_segment.dport
            if self.proto==6:
                self.__isTCP = True
                # (ACK,RST,SYN,FIN)
                self.xInfo = ((transport_segment.flags>>4)&1, (transport_segment.flags>>2)&1,                      (transport_segment.flags>>1)&1, (transport_segment.flags>>0)&1 )
        else:
            raise ValueError("Not IP Packet")
            
        # TODO : Add Application Detection
    
    @classmethod
    def inet_to_str(self,inet):
        '''
        Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
        '''
        if inet==None:
            return None
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)
    
    def getSrcIP(self): # translate HEX to DEC
        return Packet.inet_to_str(self.sip)
    
    def getDstIP(self):
        return Packet.inet_to_str(self.dip)
    
    def getSrcPort(self):
        if self.__isTransportLayer==False:
            return None
        else:
            return self.sport
    
    def getDstPort(self):
        if self.__isTransportLayer==False:
            return None
        else:
            return self.dport
    def getXInfo(self):
        if self.__isICMPQuery or self.__isTCP:
            return self.xInfo
        else:
            return None
    def getUTCTime(self):
        return datetime.datetime.utcfromtimestamp(self.timestamp)
    
    def debug_printPacket(self):
        print(self.sip, self.getSrcIP(), self.getSrcPort(), self.dip, self.getDstIP(), self.getDstPort(),              self.proto, self.protoName, self.length, self.getXInfo() ,              self.timestamp, self.getUTCTime())


# In[ ]:


class PacketFilter(object):
    
    def __init__(self,packetList, ipFilter=None, portFilter=None, timeFilter=None,lengthFilter=None,protoFilter=None):
        
        def compareIP(srcstring,dststring):
            t1 = srcstring.split('.')
            t2 = dststring.split('.')
            for ind,val in enumerate(t1) :
                if val == t2[ind] or '*' in [val, t2[ind]]:
                    continue
                else :
                    return False
            return True
                

        portgroups = portFilter.split(',')
        pRange = []
        for pg in portgroups:
            if '-' in pg:
                plb, pub = pg.split('-')
                plb ,pub = min(int(plb),int(pub)), max(int(plb),int(pub))
                for i in range(plb, pub+1):
                    pRange.append(i)
            else:
                try:
                    pRange.append(int(pg))
                except :
                    continue

        timeRange = packetList[-1].timestamp - packetList[0].timestamp
        tlb = 0
        tub = timeRange
        if timeFilter: #Syntax: timeFilter=(lowerbound:number, upperbound:number:-1=end)
            tlb = max(timeFilter[0],0)
            if timeFilter[1]!=-1:
                tub = max(min(timeFilter[1],timeRange),0)
            if tlb >= tub:
                tlb, tub = tub, tlb
        tlb = tlb + packetList[0].timestamp
        tub = tub + packetList[0].timestamp
        
        llb = 0
        lub = -1
        if lengthFilter: #Syntax lengthFilter=(lowerbound:number, upperbound:number:-1=end)
            llb = max(lengthFilter[0],0)
            lub = lengthFilter[1]
        
        pF = [1,6,17]
        if protoFilter: #Syntax protoFilter=("ICMP","UDP","TCP"):default=all
            pF= []
            if "ICMP" in protoFilter:
                pF.append(1)
            if "UDP" in protoFilter:
                pF.append(17)
            if "TCP" in protoFilter:
                pF.append(6)
        
        # port filter and ip filter are bi-lateral !!
        
        self.result = []
        for pac in packetList:
            if len(ipFilter)!=0 :
                if not compareIP(pac.getSrcIP(), ipFilter) and not compareIP(pac.getSrcIP(), ipFilter) :
                    continue
            if len(pRange)!=0 and hasattr(pac,"sport") and hasattr(pac, "dport"):
                if pac.dport not in pRange and pac.sport not in pRange:
                    continue
            if pac.timestamp<tlb or pac.timestamp>tub:
                continue
            if pac.length<llb or (lub!=-1 and pac.length>lub):
                continue
            if pac.proto not in pF:
                continue
            self.result.append(pac)
        
    def getFilteredList(self):
        return self.result
            
        
        


# In[ ]:


########READ FILE and Filter############

def Graphware_ReadNFilter(filename, ipFilter=None, portFilter=None, timeFilter=None, lengthFilter=None, protoFilter=None):
    f = open(filename,'rb')
    pcap = dpkt.pcap.Reader(f)
    c_pac_list = []
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf) # Unpack the Ethernet frame (mac src/dst, ethertype)
        # Make sure the Ethernet frame contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data
        try:
            c_packet = Packet(timestamp, ip)
            c_pac_list.append(c_packet)
        except:
            continue
    f.close()
    pfObj= PacketFilter(c_pac_list, ipFilter, portFilter, timeFilter,lengthFilter,protoFilter)
    filtered_list = pfObj.getFilteredList()

    return filtered_list



# In[ ]:


class EFP_Vertex(object):
    def __init__(self, ipaddress):
        self.hostID = ipaddress
    
    def __eq__(self,other):
        if self.hostID == other.hostID:
            return True

class EFP_Edge(object):
    def __init__(self,fromHost,toHost,linkType,extraInfo=None):
        self.head = toHost
        self.tail = fromHost
        self.linkType = linkType
        self.extraInfo = extraInfo
    
    def __eq__(self, other):
        if (self.head in [other.head,other.tail]) and             (self.tail in [other.head,other.tail]) and             self.linkType==other.linkType:
            return True
    
    def debug__Print(self):
        print(self.head, self.tail, self.linkType, self.extraInfo)
        
class EFPConverter(object):
    def __init__(self,packetList):
        self.VertexTable = []
        self.EdgeTable = []
        for pac in packetList:
            self.V_pacsrcip = EFP_Vertex(pac.getSrcIP())
            self.V_pacdstip = EFP_Vertex(pac.getDstIP())
            if self.V_pacsrcip not in self.VertexTable:
                self.VertexTable.append(self.V_pacsrcip)
            if self.V_pacdstip not in self.VertexTable:
                self.VertexTable.append(self.V_pacdstip)
            
            self.E_pac = EFP_Edge(pac.getSrcIP(),pac.getDstIP(),pac.proto)
            if self.E_pac not in self.EdgeTable:
                self.EdgeTable.append(self.E_pac)
    def makeJSON(self):
        self.jsondata = {'nodes':[], 'edges':[]}
        for v in self.VertexTable:
            self.jsondata['nodes'].append({'id': v.hostID})
        for e in self.EdgeTable:
            self.jsondata['edges'].append({                   'source': e.tail, 'target': e.head, 'type':e.linkType}) # Link Type is camcelled, which doesnot make sense
        return json.dumps(self.jsondata)
    
    def makeNetworkxObject(self):
        self.NxObj = networkx.MultiDiGraph()
        for v in self.VertexTable:
            self.NxObj.add_node(v.hostID)
        for e in self.EdgeTable:
            self.NxObj.add_edge(e.tail,e.head,type=e.linkType)
        return self.NxObj
    
    def makePyVisObject(self):
        self.PvObj = pyvis.network.Network(height="100%",width="100%",directed=True,notebook=False,bgcolor="#AAAAAA", font_color="white")
        for v in self.VertexTable:
            self.PvObj.add_node(v.hostID,size=1)
        for e in self.EdgeTable:
            self.colorD = {1:"#CCFFFF",6:"#0080FF",17:"#4C0099"}
            self.PvObj.add_edge(e.tail,e.head,physics=True,title=None,width="2px",color=self.colorD[e.linkType])
        return self.PvObj
        

class wEFPConverter(object):
    def __init__(self,packetList):
        self.VertexTable = []
        self.EdgeTable = []
        for pac in packetList:
            self.V_pacsrcip = EFP_Vertex(pac.getSrcIP())
            self.V_pacdstip = EFP_Vertex(pac.getDstIP())
            if self.V_pacsrcip not in self.VertexTable:
                self.VertexTable.append(self.V_pacsrcip)
            if self.V_pacdstip not in self.VertexTable:
                self.VertexTable.append(self.V_pacdstip)
            
            self.E_pac = EFP_Edge(pac.getSrcIP(),pac.getDstIP(),pac.proto,{})
            
            self.__flag = 0
            for pn, pinr in enumerate(self.EdgeTable):
                if pinr == self.E_pac:
                    pinr.extraInfo['count'] += 1
                    pinr.extraInfo['throughput'] += pac.length
                    pinr.extraInfo['endtime'] = pac.timestamp
                    self.__flag = 1
            if self.__flag == 0:
                self.E_pac.extraInfo['count'] = 1
                self.E_pac.extraInfo['throughput'] = pac.length
                self.E_pac.extraInfo['starttime'] = pac.timestamp
                self.E_pac.extraInfo['endtime'] = pac.timestamp
                self.EdgeTable.append(self.E_pac)
        for ent in self.EdgeTable:
            ent.extraInfo['duration'] = ent.extraInfo['endtime'] - ent.extraInfo['starttime']
    
    def makeJSON(self):
        self.jsondata = {'nodes':[], 'links':[]}
        for v in self.VertexTable:
            self.jsondata['nodes'].append({'id': v.hostID})
        for e in self.EdgeTable:
            self.jsondata['links'].append({                   'source': e.tail, 'target': e.head,                 'value' : e.extraInfo , 'type': e.linkType})
        return json.dumps(self.jsondata)
    
    def makeNetworkxObject(self):
        self.NxObj = networkx.MultiDiGraph()
        for v in self.VertexTable:
            self.NxObj.add_node(v.hostID)
        for e in self.EdgeTable:
            self.NxObj.add_edge(e.tail,e.head,type=e.linkType,count=e.extraInfo['count'],                                throughput=e.extraInfo['throughput'],duration=e.extraInfo['duration'])
        return self.NxObj
        
    
    def calculateWidth(self,w):
        return int(math.sqrt(1+w.extraInfo['throughput']/(10**5*(w.extraInfo['duration']+10e-6))))
    
    def makePyVisObject(self):
        self.PvObj = pyvis.network.Network(height="100%",width="100%",directed=False,notebook=False,bgcolor="#AAAAAA", font_color="white")        
        self.PvObj.barnes_hut()
        for v in self.VertexTable:
            self.PvObj.add_node(v.hostID)
        for e in self.EdgeTable :
            self.colorD = {1:"#CCFFFF",6:"#0080FF",17:"#4C0099"}
            
            self.PvObj.add_edge(e.tail,e.head,title=e.extraInfo['count'],                                value=self.calculateWidth(e),                                color=self.colorD[e.linkType])
        return self.PvObj
       


# In[ ]:


############ GENERATE ##########
#########DEMO ONLY############

def Graphware_Generate(paclist,resultpath):
    efpObj = EFPConverter(paclist)

    efpJson = efpObj.makeJSON()
    f=open(resultpath+'/efp.json','w')
    f.write(efpJson)
    f.close()

    #nxb = efpObj.makeNetworkxObject()
    pxb = efpObj.makePyVisObject()
    pxb.write_html(resultpath+"/efp.html")
    return resultpath

