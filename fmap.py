#! /usr/bin/env python3

Version = "1"


import sys
import os
import re
import ipaddress
import time
import argparse
import collections
import base64


from socket import inet_ntoa
from socket import getfqdn
from struct import pack
from datetime import datetime


configDir = ''
inputFile = ''
outputFilePath = ''



parser = argparse.ArgumentParser(description='fmap search configuration files for entries related to a list of IPs supports ASA/PIX/Contivity/Juniper')
parser.add_argument("-i",  dest='inputFile', help="A text file containing a list of ips, one per line.", required=True)
parser.add_argument("-c",  dest='configDir', help="Directory containing configuration files.",  required=True)
parser.add_argument("-o",  dest='outputFilePath', help="Output file path.",  required=True)
parser.add_argument("-n", help="Search for network objects.", action="store_true")
parser.add_argument("-s", help="Search for static NAT.", action="store_true")
parser.add_argument("-r", help="Search for routes.", action="store_true")
parser.add_argument("-con", help="Search contivity configuration (Local/Remote Network).", action="store_true")
parser.add_argument("-e", help="External routes only (interface name does not contain 'inside' or 'internal. )", action="store_true")
parser.add_argument("-a", help="Search for Access-Lists.", action="store_true")
parser.add_argument("-j", help="Search Juniper configuration.", action="store_true")
parser.add_argument('--version', action='version', version=Version)

args = parser.parse_args()

configDir = args.configDir
inputFile = args.inputFile
outputFilePath = args.outputFilePath
netwobject = args.n

print ("\n\nSearching firewall configuration relating to a list of IP adderesses.")
print ("-------------------------------------------------------------------------------- ")
print ("fmap initial commit by Sami Guirguis\t\t\t\t\tVersion:" ,Current Version, "\n\n")


print ("--------------------------------  Arguments  ---------------------------------- ")
print ("Search for routes       : ", args.r,  "\tExternal routes only    : ", args.e )
print ("Search Network Objects  : ", args.n,  "\tSearch for static NAT   : ", args.s)
print ("Search for Access-lists : ", args.a,  "\tSearch Contivity config : ", args.con)
print ("Search Juniper Config : ", args.j  )
print ("\n---------------------------  Files locations  --------------------------------- ")
print ("Input file path        : ", inputFile)
print ("Output file path       : ", outputFilePath)
print ("Configuration path     : ", configDir , "\n")
print ("------------------------------------------------------------------------------- ")


# check if output file can be accessed
try:
    open(outputFilePath,'w')
except IOError:
    print ("=> Cannot access output file !!")
    sys.exit()
    


outputFile = open(outputFilePath,'w')



# i is a counter for file being processed 
i = 0
# initializing sets to avoid duplicate results
setStaticContivity = set()
setHostObject = set()
setNetworkObject = set()
setStaticNat = set()
setStaticNatHost = set()
setRemoteNetworkContivity = set()
setStaticObj = set ()
setInputIPs = set()
setNextHop = set ()
setobjectNetworkHost =set()
setobjectNetworkGroupHost = set()
setobjectNetworkSubnet =set()
setobjectNetworkRange = set ()
setRoute = set()
setACE = set()

#lists to keep track of routing
listInternalRoute = []
listNoninternalRoute = []


# create dictionary for the groups
groupsDict = collections.defaultdict(set)


# start the timer

n = datetime.today()
start_time = time.time()




##
### Input file parse IPs and enter in a set
with open(inputFile, 'r', encoding="ascii", errors="surrogateescape") as infile:
    ipsInFile = re.findall  ('H?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',infile.read(),re.U)
    if ipsInFile:
        for ipInFile in ipsInFile:
                if not re.search ('^255',ipInFile):
                    ipInFile = re.sub('H0{1,2}','',ipInFile)
                    ipInFile = re.sub('\.0{1,2}(?=\d)','.',ipInFile)
                    setInputIPs.add(ipInFile)

                

# add header to output file 
outputFile.write ("Firewall name, Configuration type, IP , Subnet/Host , , Interface Name/Group Name/ACL, NAT Policy / NAT Interfaces,\n" )
                   
def connected_asa(configLine,deviceHostname):
    connected = re.search ('(ip address\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U  )
    connectedInterface = connected.group(1).strip()
    connectedNetwork = connected.group(2).strip()
    connectedNetworkMask = connected.group(3).strip()
    connectedNetworkAndMask = connectedNetwork + '/' + connectedNetworkMask
    connectedNetworkRange = ipaddress.IPv4Network(connectedNetworkAndMask,strict=False)

    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        if ip in connectedNetworkRange :
            interfaceConnectedregex = 'nameif ([a-zA-Z0-9_\.\-]+)((?!nameif).)*?' + connectedInterface 
            interfaceConnected = re.search(interfaceConnectedregex,f.read(), re.U|re.DOTALL)
            if interfaceConnected:
                outputFile.write ( deviceHostname + ",Route Connected IP :,"+ ipadd + ","+  str(connectedNetworkRange) +",Interface: ," + interfaceConnected.group(1)+",\n")
                listNoninternalRoute.append(ipadd)


def connected_pix(configLine,deviceHostname):
    connected = re.search ('(ip address\s([a-zA-Z]*)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U  )
    connectedInterface = connected.group(1).strip()
    connectedName = connected.group(2).strip()
    connectedNetwork = connected.group(3).strip()
    connectedNetworkMask = connected.group(4).strip()
    connectedNetworkAndMask = connectedNetwork + '/' + connectedNetworkMask

    connectedNetworkRange = ipaddress.IPv4Network(connectedNetworkAndMask,strict=False)

    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        if ip in connectedNetworkRange :
            outputFile.write ( deviceHostname+",Route Connected IP :,"+ ipadd + " , " +str(connectedNetworkRange) + ",Interface: ," + connectedName  + ",\n")
            listNoninternalRoute.append(ipadd)



def route(configLine,deviceHostname):
    route = re.search ('(^route\s(.*)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U)
    routeInterface = route.group(2).strip()
    routeNetwork = route.group(3).strip()
    routeNetworkMask = route.group(4).strip()
    routeNextHop = route.group(5).strip()
    routeNetworkAndMask = routeNetwork + '/' + routeNetworkMask

    routeNetworkRange = ipaddress.IPv4Network(routeNetworkAndMask,strict=False)

    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        ipadddeviceHostname = ipadd + deviceHostname
        ipadddeviceHostnameNextHop = ipadd + deviceHostname + routeNetworkAndMask

        if (ip in routeNetworkRange) and ( not args.e) and args.r and (ipadddeviceHostnameNextHop not in setRoute) :
            setRoute.add(ipadddeviceHostnameNextHop)
            outputFile.write ( deviceHostname +",Route : ,"+ ipadd + " , " + str(routeNetworkRange) + ",Interface: ," + routeInterface + ", Hop: ," + str(routeNextHop) +",\n")

        elif (ip in routeNetworkRange)and (not ( re.search ('(inside|internal|itservices)',routeInterface,re.U|re.I) )) and (args.e) and (ipadddeviceHostnameNextHop not in setRoute):
            listNoninternalRoute.append(ipadd)
            setRoute.add(ipadddeviceHostnameNextHop)
            outputFile.write ( deviceHostname + ",Route Non-internal: ,"+  ipadd + " , "+  str(routeNetworkRange) +",Interface: ," + routeInterface + ", Hop: ," + str(routeNextHop) +  ",\n")

        elif (ip in routeNetworkRange)and ( re.search ('(inside|internal|itservices)',routeInterface,re.U|re.I) ) and (args.e):
            # keep track of the number of internal routes
            listInternalRoute.append(ipadd)

        elif (ipadd == route.group(5).strip()) and (ipadddeviceHostname not in setNextHop):
            # check if the ip is a next hop and print single line per ip-device
            setNextHop.add(ipadddeviceHostname)
            outputFile.write ( deviceHostname + ",The IP is a Next-hop : ,"+  ipadd +  ",Interface: ," + routeInterface +  ",,,\n")


                                
def network_object(configLine,deviceHostname):
    networkobject = re.search ('(^ network-object\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U  )

    networkobjectNetwork = networkobject.group(2).strip()
    networkobjectNetworkMask = networkobject.group(3).strip()
    networkobjectNetworkAndMask = networkobjectNetwork + '/' + networkobjectNetworkMask

    networkobjectNetworkRange = ipaddress.IPv4Network(networkobjectNetworkAndMask,strict=False)

    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        if  (ip in networkobjectNetworkRange) :
            networkobjectregex = 'object-group network ([a-zA-Z0-9_\.\-]+)((?!object-group).)*?network-object (' + networkobjectNetwork + ' ' + networkobjectNetworkMask + ')'
            objectGroupName = re.finditer(networkobjectregex,f.read(), re.U|re.DOTALL)
            if objectGroupName:
                for objectGroupNameMatch in objectGroupName:
                    outputFile.write ( deviceHostname + ",Network Object : ,"+ ipadd +","+ networkobjectNetworkAndMask +",Object: ,"+objectGroupNameMatch.group(1) + ",\n")
                    # append the ip to the value of the dictionary key that is the firewall and the group name
                    FirewallandGroup = deviceHostname + ", Group Membership summary - network: , " + objectGroupNameMatch.group(1)
                    groupsDict[FirewallandGroup].add(ipadd)                                    
                    # get the ACLS where that group is used
                    if args.a:
                        acl_of_groups(deviceHostname,ipadd,objectGroupNameMatch.group(1),configFilePathOpen)


def host_object(configLine,deviceHostname):
    host = re.search ('(network\-object host\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))', configLine,re.U  )
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        ipadddeviceHostname = ipadd + deviceHostname
        if  (ipadd == host.group(2).strip()) and (ipadddeviceHostname not in setHostObject):
            setHostObject.add(ipadddeviceHostname)
            hostobjectregex = '(object\-group network ([a-zA-Z0-9_\.\-]+)((?!object\-group).)*?(network\-object host ' + ipadd.replace(".","\.") + '$))'
            hostobjectName = re.finditer(hostobjectregex,f.read(),re.U | re.S | re.M)
            if hostobjectName:
                for hostobjectNameMatch in hostobjectName:
                    outputFile.write ( deviceHostname +",Network Object : ,"+ ipadd + ",host ,Object: ,"+hostobjectNameMatch.group(2)+ ", "+ hostobjectNameMatch.group(4) + ",\n")
                    # append the ip to the value of the dictionary key that is the firewall and the group name
                    FirewallandGroup = deviceHostname + ", Group Membership summary - host: , " + hostobjectNameMatch.group(2)
                    groupsDict[FirewallandGroup].add(ipadd)
                    # get the ACLS where that group is used
                    if args.a:
                        acl_of_groups(deviceHostname,ipadd,hostobjectNameMatch.group(2),configFilePathOpen)



def object_network_host(configLine,deviceHostname):
    objectNetworkHost =  re.search ('(^\shost\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))', configLine,re.U  )
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        ipadddeviceHostname = ipadd + deviceHostname
        if  (ipadd == objectNetworkHost.group(2).strip()) and (ipadddeviceHostname not in setobjectNetworkHost):
            setobjectNetworkHost.add(ipadddeviceHostname)
            objectNetworkHostRegex = '(object network ([a-zA-Z0-9_\.\-]+)((?!object).)*?\shost\s(' + ipadd.replace(".","\.") + '))'
            objectNetworkHostName = re.finditer(objectNetworkHostRegex,f.read(),re.U| re.S)
            if objectNetworkHostName:
                for objectNetworkHostNameMatch in objectNetworkHostName:
                    outputFile.write ( deviceHostname +",Network Object : ,"+ ipadd + ",host ,Object: ,"+objectNetworkHostNameMatch.group(2)+ ", "+ objectNetworkHost.group() + ",\n")
                    # append the ip to the value of the dictionary key that is the firewall and the group name
                    FirewallandGroup = deviceHostname + ", Group Membership summary - host: , " + objectNetworkHostNameMatch.group(2)
                    groupsDict[FirewallandGroup].add(ipadd)
                    # get the ACLS where that group is used
                    if args.a:
                        acl_of_groups(deviceHostname,ipadd,objectNetworkHostNameMatch.group(2),configFilePathOpen)



def object_network_h0(configLine,deviceHostname):
    objectNetworkGroupHost =  re.search ('(^\sgroup-object\s([HN\.0-9]+))', configLine,re.U  )
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        HNorIpadd = "H?N?0{0,2}" + ipadd.replace(".","\.0{0,2}")
        HipadddeviceHostname = HNorIpadd + deviceHostname
        if (re.search(HNorIpadd,objectNetworkGroupHost.group(2),re.U) ):
            objectNetworkGroupHostRegex = '(object\-group network ([a-zA-Z0-9_\.\-]+)((?!(object\-group)).)*?\sgroup\-object\s' + objectNetworkGroupHost.group(2) + ')'
            objectNetworkGroupHostName = re.finditer(objectNetworkGroupHostRegex,f.read(),re.U| re.S)
            if objectNetworkGroupHostName and (HipadddeviceHostname not in setobjectNetworkGroupHost) :
                for objectNetworkGroupHostNameMatch in objectNetworkGroupHostName:
                    setobjectNetworkGroupHost.add(HipadddeviceHostname)
                    #print( objectNetworkGroupHostNameMatch.group(2))
                    outputFile.write ( deviceHostname +",Network Object : ,"+ ipadd + ",host ,Object: ,"+objectNetworkGroupHostNameMatch.group(2)+ ", "+ objectNetworkGroupHost.group() + ",\n")
                    # get the ACLS where that group is used
                    if args.a:
                        acl_of_groups(deviceHostname,ipadd,objectNetworkGroupHostNameMatch.group(2),configFilePathOpen)

    

def object_network_subnet(configLine,deviceHostname):
    objectNetworkSubnet =  re.search ('(^\ssubnet\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))', configLine,re.U  )
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        ipadddeviceHostname = ipadd + deviceHostname
        objectNetworkSubnetAndMask = objectNetworkSubnet.group(2) + "/" + objectNetworkSubnet.group(3)
        objectNetworkSubnetRange = ipaddress.IPv4Network(objectNetworkSubnetAndMask,strict=False)

        if  (ip in objectNetworkSubnetRange) and (ipadddeviceHostname not in setobjectNetworkSubnet):
            setobjectNetworkSubnet.add(ipadddeviceHostname)
            objectNetworkSubnetRegex = '(object network ([a-zA-Z0-9_\.\-]+)((?!object).)*?\ssubnet\s(' + objectNetworkSubnet.group(2).replace(".","\.") + " " + objectNetworkSubnet.group(3).replace(".","\.")+ '))'
            #print (objectNetworkHostRegex)  # <<< Do not use start of line ^ in this regex, it will mean start of the file
            objectNetworkSubnetName = re.finditer(objectNetworkSubnetRegex,f.read(),re.U| re.S)
            #print ("1", deviceHostname,objectNetworkHost.group(2), "\n")
            if objectNetworkSubnetName:
                for objectNetworkSubnetNameMatch in objectNetworkSubnetName:
                    outputFile.write ( deviceHostname +",Network Object : ,"+ ipadd + ", " +objectNetworkSubnetAndMask + " , Object: ,"+objectNetworkSubnetNameMatch.group(2)+ ",\n")
                    # append the ip to the value of the dictionary key that is the firewall and the group name
                    FirewallandGroup = deviceHostname + ", Group Membership summary - network: , " + objectNetworkSubnetNameMatch.group(2)
                    groupsDict[FirewallandGroup].add(ipadd)                                        
                    # get the ACLS where that group is used
                    if args.a:
                        acl_of_groups(deviceHostname,ipadd,objectNetworkSubnetNameMatch.group(2),configFilePathOpen)



def object_network_range(configLine,deviceHostname):
    objectNetworkRange =  re.search ('(^\srange\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))', configLine,re.U  )
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        ipadddeviceHostname = ipadd + deviceHostname
        rangeStart = ipaddress.IPv4Address(objectNetworkRange.group(2))
        rangeEnd = ipaddress.IPv4Address(objectNetworkRange.group(3))
        if  (ip > rangeStart) and (ip < rangeEnd) and (ipadddeviceHostname not in setobjectNetworkRange):
            setobjectNetworkRange.add(ipadddeviceHostname)
            objectNetworkRangeRegex = '(object network ([a-zA-Z0-9_\.\-]+)((?!object).)*?\srange\s(' + objectNetworkRange.group(2).replace(".","\.") + " " + objectNetworkRange.group(3).replace(".","\.")+ '))'
            #print (objectNetworkHostRegex)  # <<< Do not use start of line ^ in this regex, it will mean start of the file
            objectNetworkRangeName = re.finditer(objectNetworkRangeRegex,f.read(),re.U| re.S)
            #print ("1", deviceHostname,objectNetworkHost.group(2), "\n")
            if objectNetworkRangeName:
                for objectNetworkRangeNameMatch in objectNetworkRangeName:
                    outputFile.write ( deviceHostname +",Network Object : ,"+ ipadd + ", " +objectNetworkRange.group(2)+"-"+objectNetworkRange.group(3) + " , Object: ,"+objectNetworkRangeNameMatch.group(2)+ ",\n")
                    # append the ip to the value of the dictionary key that is the firewall and the group name
                    FirewallandGroup = deviceHostname + ", Group Membership summary - network: , " + objectNetworkRangeNameMatch.group(2)
                    groupsDict[FirewallandGroup].add(ipadd)
                    # get the ACLS where that group is used
                    if args.a:
                        acl_of_groups(deviceHostname,ipadd,objectNetworkRangeNameMatch.group(2),configFilePathOpen)




def static(configLine,deviceHostname):
    static = re.search('(^static\s\((.+),(.+)\)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U )
    # if the line is a static command search all the ips in the input file if there is a match
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        if ( ipadd == static.group(4).strip() ) :
            outputFile.write (deviceHostname +",Static NAT:,"+ipadd+  ",NAT to:," + static.group(5) +",Interfaces: ," +static.group(3) + " ---> " +static.group(2)+ ",\n")
        elif (ipadd == static.group(5).strip()):
            outputFile.write (deviceHostname +",Static NAT:,"+ipadd+  ",NAT to:," + static.group(4) +",Interfaces: ," +static.group(2) + " ---> " +static.group(3)+ ",\n")




def static_contivity(configLine,deviceHostname):
    staticContivity = re.search('(^rule add action static source \"[a-zA-Z_-]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U )
    # if the line is a static command search all the ips in the input file if there is a match
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        ipadddeviceHostname = ipadd + deviceHostname
        if ( ipadd == staticContivity.group(2)) and (ipadddeviceHostname not in setStaticContivity):
            setStaticContivity.add(ipadddeviceHostname)
            staticContivityRegex = '(policy nat \"([a-zA-Z0-9_\.\-]*)\"((?!policy).)*?rule add action static source \"[a-zA-Z_-]+' + ipadd.replace(".","\.") +'((?!rule).)*?(\"[a-zA-Z_-]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})))'
            staticContivityMatches = re.finditer(staticContivityRegex,f.read(),re.U |re.DOTALL)
            #print (staticContivityMatches)
            if staticContivityMatches:
                for staticContivityMatch in staticContivityMatches:
                    outputFile.write (deviceHostname +",Static Contivity: ,"+ipadd+  ",NAT to:," + staticContivityMatch.group(6) + ", NAT Policy: ," +  staticContivityMatch.group(2) + ",\n")
                                

def static_object(configLine,deviceHostname):
    staticObj =  re.search('(^object network (ANAT|obj|host-obj)\-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U|re.I)
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        ipadddeviceHostname = ipadd + deviceHostname
        if ( ipadd == staticObj.group(3).strip())and (ipadddeviceHostname not in setStaticObj):
            setStaticObj.add(ipadddeviceHostname)
            staticObjRegex = '(object network (ANAT|obj|host-obj)\-' + ipadd.replace(".","\.") +'((?!\d).)*\n\s(nat\s\((.+),(.+)\)\sstatic\s(mapped-obj-)?(.*)))'
            staticObjNameMatches = re.finditer(staticObjRegex,f.read(),re.U|re.I )
            if staticObjNameMatches:
                for staticObjName in staticObjNameMatches:
                    outputFile.write (deviceHostname +",Static NAT:,"+ipadd+  ",NAT to: ," + staticObjName.group(8) +",Interfaces: ," +staticObjName.group(5) + "  ----> " +staticObjName.group(6)+",\n")


def static_object_reverse(configLine,deviceHostname):
    staticObjReverse =  re.search('(^\snat\s\((.+),(.+)\)\sstatic\s(mapped-obj-)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U)
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        f = open (configFilePath,'r')
        if ( ipadd == staticObjReverse.group(5).strip()):
            # withnodigits staticObjReverseRegex = '(object network (ANAT|obj|host-obj)\-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})((?!\d).)*\n\s(nat\s\((.+),(.+)\)\sstatic\s(mapped-obj-)?' + ipadd.replace(".","\.") +'))'
            staticObjReverseRegex = '(object network (ANAT|obj|host-obj)\-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(.*)\n\s(nat\s\((.+),(.+)\)\sstatic\s(mapped-obj-)?' + ipadd.replace(".","\.") +'))'
            #print (staticObjReverseRegex)
            staticObjReverseNameMatches = re.finditer(staticObjReverseRegex,f.read(),re.U )
            if staticObjReverseNameMatches:
                for staticObjReverseName in staticObjReverseNameMatches:
                    outputFile.write (deviceHostname +",Static NAT:,"+ipadd+  ",NAT to: ," + str(staticObjReverseName.group(3)) +",Interfaces: ," +str(staticObjReverseName.group(6)) + "  ----> " + str(staticObjReverseName.group(7))+",\n")


def nat(configLine,deviceHostname):
    nat = re.search('(^nat\s.+\s.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U )
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        #print ("***** NAT GROUP @ ****",nat.group(2))
        ipadddeviceHostname = ipadd + deviceHostname
        if ipadd == nat.group(2).strip() and (ipadddeviceHostname not in setStaticNat):
            setStaticNat.add(ipadddeviceHostname)
            outputFile.write (deviceHostname +",Static NAT: ,"+ipadd+ ", ," +nat.group() + ",\n")

def static_dynamic_hn(configLine,deviceHostname):
    nathost = re.search('(^nat\s\((.+),(.+)\).*source (static|dynamic)\s(host-|obj-)?([HN\d\.]+)\s(host-|obj-)?([HN\d\.]+))',configLine, re.U |re.I)
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        #print ("***** NAT GROUP @ ****",nat.group(2))
        ipadddeviceHostname = ipadd + deviceHostname
        # To account for H010.0x.x.x 
        HNorIpadd = "H?N?0{0,2}" + ipadd.replace(".","\.0{0,2}")
        if ipadd == nathost.group(8).strip() :
            outputFile.write (deviceHostname +",Static NAT: ,"+ipadd+ ",NAT to:," +nathost.group(6)  +",Interfaces: ," +nathost.group(3) + "  ----> " +nathost.group(2) +",\n")
        elif  ipadd == nathost.group(6).strip()  :
            outputFile.write (deviceHostname +",Static NAT: ,"+ipadd+ ",NAT to:," +nathost.group(8)+",Interfaces: ," +nathost.group(2) + "  ----> " +nathost.group(3) +",\n")
        elif re.search(HNorIpadd,configLine, re.U |re.I):
            outputFile.write (deviceHostname +",Static NAT: ,"+ipadd+ ",NAT to:," +nathost.group(8)+"-"+nathost.group(6)+",Interfaces: ," +nathost.group(2) + "  ---- " +nathost.group(3) +",\n")



def global_nat(configLine,deviceHostname):
    globalnat = re.search('(^global\s.+\s\d\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U )
    # if the line is a nat command search all the ips in the input file if there is a match
    # print ('******** NAT **********')
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)

        if ipadd == globalnat.group(2).strip():
            outputFile.write (deviceHostname +",Static NAT: ,"+ipadd+  ", ," + globalnat.group(1) +  ",\n")



def access_list(configLine,deviceHostname):
    # Two subnets
    wholeline = re.search('(access-list.*)',configLine, re.U )
    acltwosubnet = re.search('(^access-list.*\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U )
    aclonesubnet = re.search('(^access-list.*\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(host|object|eq|any|range|echo|traceroute|$))',configLine, re.U )
    aclonlyhost = re.search('(^access-list((?!255).)*$)',configLine, re.U )

    if acltwosubnet :

        sourcesubnet = acltwosubnet.group(2) + '/' +  acltwosubnet.group(3)
        sourcesubnetRange = ipaddress.IPv4Network(sourcesubnet,strict=False)
        destsubnet = acltwosubnet.group(4) + '/' +  acltwosubnet.group(5)
        destsubnetRange = ipaddress.IPv4Network(destsubnet,strict=False)
        for addr in setInputIPs:
            'remove white space'
            ipadd = addr.strip()
            ip = ipaddress.IPv4Address(ipadd)
            # To avoid dupes
            FirewallIPACE = deviceHostname + ipadd + wholeline.group(1)

            if (ip in sourcesubnetRange ) and (FirewallIPACE not in setACE):
                setACE.add(FirewallIPACE)
                outputFile.write (deviceHostname +",Access-List : ,"+ipadd+  ","+ sourcesubnet+", ACE:," + wholeline.group(1) + ",\n")
            elif (ip in destsubnetRange) and (FirewallIPACE not in setACE):
                setACE.add(FirewallIPACE)
                outputFile.write (deviceHostname +",Access-List : ,"+ipadd+  ","+ destsubnet+" , ACE:," + wholeline.group(1) + ",\n")

            elif aclonesubnet :
                    onesubnet = aclonesubnet.group(2) + '/' +  aclonesubnet.group(3)
                    onesubnetRange = ipaddress.IPv4Network(onesubnet,strict=False)
                    for addr in setInputIPs:
                        'remove white space'
                        ipadd = addr.strip()
                        ip = ipaddress.IPv4Address(ipadd)
                        ipaddonly = "host\s"+ ipadd + "\s"
                        # case where the ip is in the range
                        FirewallIPACE = deviceHostname + ipadd + wholeline.group(1)
                        # To account for H010.0x.x.x 
                        HNorIpadd = "H?N?0{0,2}" + ipadd.replace(".","\.0{0,2}")
                        if (ip in onesubnetRange) and (FirewallIPACE not in setACE):
                            setACE.add(FirewallIPACE)
                            outputFile.write (deviceHostname +",Access-List : ,"+ipadd+  ", "+ onesubnet+" , ACE:," + wholeline.group(1) + ",\n")
                        elif re.search(HNorIpadd,wholeline.group(1), re.U ) and (FirewallIPACE not in setACE):
                            setACE.add(FirewallIPACE)
                            outputFile.write (deviceHostname +",Access-List : ,"+ipadd+  ", host , ACE:," + wholeline.group(1) + ",\n")

                        elif aclonlyhost :
                            for addr in setInputIPs:
                                'remove white space'
                                ipadd = addr.strip()
                                ip = ipaddress.IPv4Address(ipadd)
                                ipaddonly = ipadd + "\s"
                                FirewallIPACE = deviceHostname + ipadd + wholeline.group(1)
                                # To account for H010.0x.x.x 
                                HNorIpadd = "H?N?0{0,2}" + ipadd.replace(".","\.0{0,2}")
                                if re.search(HNorIpadd,wholeline.group(1), re.U ) and (FirewallIPACE not in setACE):
                                    setACE.add(FirewallIPACE)
                                    outputFile.write (deviceHostname +",Access-List : ,"+ipadd+  ", host , ACE:," + wholeline.group(1) + ",\n")

                        
def remote_network_contivity(configLine,deviceHostname):
    remotenetwork = re.search('(remote-network\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\smask\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U )
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        remotenetworkNetworkAndMask = remotenetwork.group(2) + '/' + remotenetwork.group(3)
        remotenetworkRange = ipaddress.IPv4Network(remotenetworkNetworkAndMask,strict=False)
        f = open (configFilePath,'r')


        if ( ip in remotenetworkRange ) or (ipadd == remotenetwork.group(2)):
            remotenetworkRegex = 'local-network \"([a-zA-Z0-9_\.\-]+)\"((?!local-network).)*?remote-network (' + remotenetwork.group(2) + ' mask ' + remotenetwork.group(3) + ')'
            localnetworkName = re.finditer(remotenetworkRegex,f.read(), re.U|re.DOTALL)
            if localnetworkName:
                for localnetworkNameMatch in localnetworkName:
                    ipdevicelocalnetwork = ipadd + deviceHostname + localnetworkNameMatch.group(1)
                    if ipdevicelocalnetwork not in setRemoteNetworkContivity:
                        setRemoteNetworkContivity.add(ipdevicelocalnetwork)
                        outputFile.write ( deviceHostname +",Contivity Remote-network:,"+ ipadd + ","+ remotenetworkNetworkAndMask +", in ," +localnetworkNameMatch.group(1) + ",\n")


def local_network_contivity(configLine,deviceHostname):
    localnetwork = re.search('(^network add \"([a-zA-Z0-9_\.\-]+)\"\sip\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\smask\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U )
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        localnetworkandmask = localnetwork.group(3) + '/' + localnetwork.group(4)
        localnetworkrange = ipaddress.IPv4Network(localnetworkandmask,strict=False)
        if (ip in localnetworkrange ) or (ipadd == localnetwork.group(3)):
            outputFile.write (  deviceHostname +",Contivity Local-network:,"+ ipadd + ","+ localnetworkandmask +", in ,"+localnetwork.group(2)+",\n")
                                


def juniper_network_group(configLine,deviceHostname):
    juniperGroup = re.search('(^set address\s\"(.*)\"\s\"(.*)\"\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U)
    #with open(inputFile, 'r') as infile:
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        juniperGroupnetandmask = juniperGroup.group(4) + '/' + juniperGroup.group(5)
        juniperGrouprange = ipaddress.IPv4Network(juniperGroupnetandmask,strict=False)
        if (ip in juniperGrouprange ) or (ipadd == juniperGroup.group(4)):
            outputFile.write (  deviceHostname +",Juniper Group:,"+ ipadd + ","+ str(juniperGrouprange) +", in ,"+juniperGroup.group(3)+",\n")

def juniper_interface(configLine,deviceHostname):
    juniperInterface = re.search('(^set interface (.*) ip ((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})))',configLine, re.U)
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        juniperInterfacerange = ipaddress.IPv4Network(juniperInterface.group(3),strict=False)
        if (ip in juniperInterfacerange ) or (ipadd == juniperInterface.group(4)):
            outputFile.write (  deviceHostname +",Juniper Interface:,"+ ipadd + ","+ str(juniperInterfacerange) +", out of ,"+juniperInterface.group(2)+",\n")

def juniper_nat_mip(configLine,deviceHostname):
    juniperMIP = re.search('(^set interface \"(.*)\" mip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) host (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U)
    for addr in setInputIPs:
        'remove white space'
        ipadd = addr.strip()
        ip = ipaddress.IPv4Address(ipadd)
        if (ipadd == juniperMIP.group(4)):
            outputFile.write (  deviceHostname +",Juniper MIP:,"+ ipadd + ",NAT to:,"+ juniperMIP.group(3) +", out of ,"+juniperMIP.group(2)+",\n")
        elif (ipadd == juniperMIP.group(3)):
            outputFile.write (deviceHostname +",Juniper MIP:,"+ ipadd + ",NAT to:,"+ juniperMIP.group(4) +", out of ,"+juniperMIP.group(2)+",\n")



# find the acls using the group where the ip belongs to
def acl_of_groups(deviceHostname,ipadd,groupname,configFilePath):
    print(deviceHostname,ipadd,groupname,configFilePath)
    with open(configFilePath,encoding="ascii", errors="surrogateescape") as configFilePathOpen:
        acl_using_group_pattern = "^access-list.*" + groupname
        acls_using_group = re.findall(acl_using_group_pattern,configFilePathOpen,re.U)
        for acl_using_group in acls_using_group:
            outputFile.write (deviceHostname +",Access List:,"+ ipadd +","+groupname + ",ACE:,"+ acl_using_group.group(0)+",\n")
                
                
                

########################################## Main loop on config files  #############################################
###################################################################################################################
for subdir, dirs, configFiles in os.walk(configDir):
        # Open each config file, and go through each line, if the line is a route loop through the input ips and check if they are in the range of the route up to /16
        # Same goes for objects, static, nat ....
        for configFile in configFiles:
            configFilePath = os.path.join(subdir, configFile)
            i += 1
            print ("Processing files : ", "\t", int((i*100.0)/len(configFiles)),"%" , end="\r",flush=True)
            
            with open(configFilePath,encoding="ascii", errors="surrogateescape") as configFilePathOpen:
                
                configFileOpen = open (configFilePath,'r')

                deviceHostnameConfig = re.search ('hostname (.*)',configFileOpen.read(),re.U)
                if deviceHostnameConfig:
                    deviceHostname = deviceHostnameConfig.group(1)
                else:
                    deviceHostname = configFile
                configFileOpen.close()
                
                                                                                       

                for configLine in configFilePathOpen:
                    # Connected ASA
                    if (args.e or args.r) and re.search ('(ip address\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U  ):
                        connected_asa(configLine,deviceHostname)
                    # Connected PIX
                    elif (args.e or args.r) and re.search ('(ip address\s([a-zA-Z]*)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U  ):
                        connected_pix(configLine,deviceHostname)
                    # Route
                    elif (args.e or args.r) and re.search ('(^route\s(.*)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U):
                        route(configLine,deviceHostname)
                    # Network Object
                    elif (netwobject) and re.search ('(^ network-object\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U):
                        network_object(configLine,deviceHostname)
                    # Host Object
                    elif (netwobject) and re.search ('(network\-object host\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))', configLine,re.U):
                        # if the configuration line is a host networkobject search all the ips in the input file if there is a match                        
                        host_object(configLine,deviceHostname)
                    # object network - host
                    elif (netwobject) and re.search ('^ host',configLine,re.U):
                        object_network_host(configLine,deviceHostname)
                    # object network - H0
                    elif (netwobject) and re.search ('(^\sgroup-object\s([HN\.0-9]+))',configLine,re.U):
                        object_network_h0(configLine,deviceHostname)
                    # object network - subnet
                    elif (netwobject) and re.search ('^ subnet',configLine,re.U):
                        object_network_subnet(configLine,deviceHostname)
                    # object network - range
                    elif (netwobject) and re.search ('^ range',configLine,re.U  ):
                        object_network_range(configLine,deviceHostname)
                    # Static
                    elif args.s and re.search('(^static\s.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U ) :
                        static(configLine,deviceHostname)
                    # Static Contivity
                    elif args.s and re.search('(^rule add action static source)',configLine, re.U ):
                        static_contivity(configLine,deviceHostname)
                    # static with object
                    elif args.s and re.search('(^object\snetwork\s(ANAT|obj|host-obj)-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U|re.I):
                        static_object(configLine,deviceHostname)
                    # Reverse static with object
                    elif args.s and re.search('(^\snat\s\((.+),(.+)\)\sstatic\s(mapped-obj-)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine,re.U):
                        static_object_reverse(configLine,deviceHostname)
                    # NAT        
                    elif args.s and re.search('(^nat\s.+\s.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U ):
                        nat(configLine,deviceHostname)
                    # static NAT host or H0 or N0
                    elif args.s and re.search('(^nat\s\((.+),(.+)\).*source (static|dynamic)\s(host-|obj-)?([HN\d\.]+)\s(host-|obj-)?([HN\d\.]+))',configLine, re.U |re.I):
                        static_dynamic_hn(configLine,deviceHostname)
                    # global nat
                    elif args.s and re.search('(^global\s.+\s\d\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U ):
                        global_nat(configLine,deviceHostname)
                    #access-lists 
                    elif args.a and re.search('(^access-list)',configLine, re.U ):
                        access_list(configLine,deviceHostname)
                    # remote-network contivity
                    elif args.con and re.search('(^remote-network)',configLine, re.U):
                        remote_network_contivity(configLine,deviceHostname)
                    # local-network contivity
                    elif args.con and re.search('(^network add \"([a-zA-Z0-9_\.\-]+)\"\sip\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\smask\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U):
                        local_network_contivity(configLine,deviceHostname)
                    # Juniper network group
                    elif args.j and re.search('(^set address\s\"(.*)\"\s\"(.*)\"\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(255\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U):
                        juniper_network_group(configLine,deviceHostname)
                    # Juniper interface
                    elif args.j and re.search('(^set interface (.*) ip ((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})))',configLine, re.U):
                        juniper_interface(configLine,deviceHostname)
                    # Juniper Nat mip
                    elif args.j and re.search('(^set interface \"(.*)\" mip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) host (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',configLine, re.U):
                        juniper_nat_mip(configLine,deviceHostname)
                        
########################################## END Main loop on config files  #############################################
###################################################################################################################                     

# Checking routing status and adding to output file
#with open(inputFile, 'r') as infile:
for ip in setInputIPs:
    if (ip.strip() in listInternalRoute ) and not(ip.strip() in listNoninternalRoute) and (args.e):
        outputFile.write ("Route Internal Zone : ,Routes ,"+ip.strip()+", count of internal routes "+str(listInternalRoute.count(ip.strip())) +",-,-,-,-,\n")
    elif (ip.strip() not in listInternalRoute ) and (ip.strip() not in listNoninternalRoute) and (args.e or args.r):
        outputFile.write ("No Routes for: , None , "+ip.strip()+",-,-,-,-,-\n")


# checking IPs that are in the same group
for i in groupsDict.keys():
    outputFile.write (str(i)+", Contains the following IPs: ,"+", ".join(groupsDict[i])+",-,-,-\n")

 
    
outputFile.close()


print("Processing complete in : ", " %s seconds " % round((time.time() - start_time)))



