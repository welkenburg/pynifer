from socket import *
import struct
import sys
import re
import pandas as pd
import datetime
import msvcrt

#pause funcion
def kbfunc():
    x = msvcrt.kbhit()
    if x:
        ret = msvcrt.getch()
    else:
        ret = False
    return ret


# receive a datagram
def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except timeout:
        data = ''
    except:
        print ("An error happened: ")
        sys.exc_info()
    return data[0]
 
# get Type of Service: 8 bits
def getTOS(data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}
 
#   get the 3rd bit and shift right
    D = data & 0x10
    D >>= 4
#   get the 4th bit and shift right
    T = data & 0x8
    T >>= 3
#   get the 5th bit and shift right
    R = data & 0x4
    R >>= 2
#   get the 6th bit and shift right
    M = data & 0x2
    M >>= 1
#   the 7th bit is empty and shouldn't be analyzed
 
    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + "; " + delay[D] + "; " + throughput[T] + "; " + \
            reliability[R] + "; " + cost[M]
    return TOS
 
# get Flags: 3 bits
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}
 
#   get the 1st bit and shift right
    R = data & 0x8000
    R >>= 15
#   get the 2nd bit and shift right
    DF = data & 0x4000
    DF >>= 14
#   get the 3rd bit and shift right
    MF = data & 0x2000
    MF >>= 13
 
    flags = flagR[R] + "; " + flagDF[DF] + "; " + flagMF[MF]
    return flags
 
# get protocol: 8 bits
def getProtocol(protocolNr):
    if protocolNr == 6:
        protocol = 'TCP'
    elif protocolNr == 17:
    	protocol = 'UDP'
    elif protocolNr == 1:
    	protocol = 'ICMP'
    else:
    	protocol = protocolNr
    return protocol

#get ICMP type: 8 bits
def gettype(cmtype):
    typeofcontrol = {
       0:'Echo Reply',
       3:'Destination Unreachable',
       4:'Source Quench',
       5:'Redirect Message',
       8:'Echo Request',
       9:'Router Advertisement',
       10:'Router Solicitation',
       11:'Time Exceeded',
       12:'Parameter Problem: Bad IP header',
       13:'Timestamp',
       14:'Timestamp Reply',
       15:'Information Request',
       16:'Information Reply',
       17:'Address Mask Request',
       18:'Address Mask Reply',
       30:'Traceroute',
       42:'Extended Echo Request',
       43:'Extended Echo Reply'
    }
    return typeofcontrol.get(cmtype,cmtype)

#get ICMP: 8 bits
def getcode(codenumber):
    if unpacked_ICMP_data[0] == 0:
        return 'Echo reply (used to ping)'
    elif unpacked_ICMP_data[0] == 1 or unpacked_ICMP_data[0] == 2 :
        return 'Reserved'
    elif unpacked_ICMP_data[0] == 3:
        typofcode = {
            0:'Destination network unreachable',
            1:'Destination host unreachable',
            2:'Destination protocol unreachable',
            3:'Destination port unreachable',
            4:'Fragmentation required, and DF flag set',
            5:'Source route failed',
            6:'Destination network unknown',
            7:'Destination host unknown',
            8:'Source host isolated',
            9:'Network administratively prohibited',
            10:'Host administratively prohibited',
            11:'Network unreachable for ToS',
            12:'Host unreachable for ToS',
            13:'Communication administratively prohibited',
            14:'Host Precedence Violation',
            15:'Precedence cutoff in effect'
        }
        return typofcode.get(codenumber,codenumber)
    elif unpacked_ICMP_data[0] == 4:
        return 'Source quench (congestion control)'
    elif unpacked_ICMP_data[0] == 5:
        typofcode = {
            0:'Redirect Datagram for the Network',
            1:'Redirect Datagram for the Host',
            2:'Redirect Datagram for the ToS & network',
            3:'Redirect Datagram for the ToS & host'
        }
        return typofcode.get(codenumber,codenumber)
    elif unpacked_ICMP_data[0] == 6:
        return 'Alternate Host Address'
    elif unpacked_ICMP_data[0] == 7:
        return 'Reserved'
    elif unpacked_ICMP_data[0] == 8:
        return 'Echo request (used to ping)'
    elif unpacked_ICMP_data[0] == 9:
        return 'Router Advertisement'
    elif unpacked_ICMP_data[0] == 10:
        return 'Router discovery/selection/solicitation'
    elif unpacked_ICMP_data[0] == 11:
        typofcode = {
            0:'TTL expired in transit',
            1:'Fragment reassembly time exceeded'
        }
        return typofcode.get(codenumber,codenumber)
    elif unpacked_ICMP_data[0] == 12:
        typofcode = {
            0:'Pointer indicates the error',
            1:' Missing a required option',
            2:'Bad length'
        }
        return typofcode.get(codenumber,codenumber)
    elif unpacked_ICMP_data[0] == 13:
        return 'Timestamp'
    elif unpacked_ICMP_data[0] == 14:
        return 'Timestamp reply'
    elif unpacked_ICMP_data[0] == 15:
        return 'Information Request'
    elif unpacked_ICMP_data[0] == 16:
        return 'Information Reply'
    elif unpacked_ICMP_data[0] == 17:
        return 'Address Mask Request'
    elif unpacked_ICMP_data[0] == 18:
        return 'Address Mask Reply'
    elif unpacked_ICMP_data[0] == 19:
        return 'Reserved for security'
    elif unpacked_ICMP_data[0] >= 20 and unpacked_ICMP_data[0] <= 29:
        return 'Reserved for robustness experiment'
    elif unpacked_ICMP_data[0] == 30:
        return 'Information Request'
    elif unpacked_ICMP_data[0] == 31:
        return 'Datagram Conversion Error'
    elif unpacked_ICMP_data[0] == 32:
        return 'Mobile Host Redirect'
    elif unpacked_ICMP_data[0] == 33:
        return 'Where-Are-You (originally meant for IPv6)'
    elif unpacked_ICMP_data[0] == 34:
        return 'Here-I-Am (originally meant for IPv6)'
    elif unpacked_ICMP_data[0] == 35:
        return 'Mobile Registration Request'
    elif unpacked_ICMP_data[0] == 36:
        return 'Mobile Registration Reply'
    elif unpacked_ICMP_data[0] == 37:
        return 'Domain Name Request'
    elif unpacked_ICMP_data[0] == 38:
        return 'Domain Name Reply'
    elif unpacked_ICMP_data[0] == 39:
        return 'SKIP Algorithm Discovery Protocol, Simple Key-Management for Internet Protocol'
    elif unpacked_ICMP_data[0] == 40:
        return 'Photuris, Security failures'
    elif unpacked_ICMP_data[0] == 41:
        return 'ICMP for experimental mobility protocols such as Seamoby'
    elif unpacked_ICMP_data[0] == 42:
        return 'Request Extended Echo (XPing)'
    elif unpacked_ICMP_data[0] == 43:
        typofcode = {
            0:'No Error',
            1:'Malformed Query',
            2:'No Such Interface',
            3:'No Such Table Entry',
            4:'Multiple Interfaces Satisfy Query'
        }
        return typofcode.get(codenumber,codenumber)
    elif unpacked_ICMP_data[0] >= 44 and unpacked_ICMP_data[0] <= 252:
        return 'Reserved'
    elif unpacked_ICMP_data[0] == 253:
        return 'RFC3692-style Experiment 1'
    elif unpacked_ICMP_data[0] == 254:
        return 'RFC3692-style Experiment 2'
    elif unpacked_ICMP_data[0] == 255:
        return 'Reserved'

#translate data form ICMP packets
def translatedata(icmp_raw_data):
    #the data is: ICMP header + 8 first bits of data
    if icmp_type == 4 or icmp_type == 11:
        icmpdata = ''.join(chr(i) for i in icmp_raw_data[4:])
        icmpcsv = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)),str((ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(icmp_type),str(icmp_code),str(icmp_checksum),str(icmpdata)]], columns= ['Date','Size','Version','Header Length','Type of Service','Length','hex ID','str ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','type','code','checksum','data'])
    #the data is: the IP adress + ICMP header + 8 first bits of data
    elif icmp_type == 5:
        icmp_unpacked_data = struct.unpack('!4s' , icmp_raw_data[:4])
        icmp_ip = inet_ntoa(unpackedData[0])
        icmpdata = ''.join(chr(i) for i in icmp_raw_data[4:])
        icmpcsv = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)),str((ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(icmp_type),str(icmp_code),str(icmp_checksum),str(icmp_ip),str(icmpdata)]], columns= ['Date','Size','Version','Header Length','Type of Service','Length','hex ID','str ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','type','code','checksum','IP Address','data'])
    #the data is: the identifier the sequence number + the originate timestamp + the receive timestamp + the transmit timestamp + ICMP header + 8 first bits of data
    elif icmp_type == 13 or icmp_type == 14:
        icmp_unpacked_data = struct.unpack('!HHLLL' , icmp_raw_data[:16])
        icmp_identifier = icmp_unpacked_data[0]
        icmp_sequence_number = icmp_unpacked_data[1]
        icmp_originate_timestamp = icmp_unpacked_data[2]
        icmp_receive_timestamp = icmp_unpacked_data[3]
        icmp_transmit_timestamp = icmp_unpacked_data[4]
        icmpdata = ''.join(chr(i) for i in icmp_raw_data[16:])
        icmpcsv = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)),str((ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(icmp_type),str(icmp_code),str(icmp_checksum),str(icmp_identifier),str(icmp_sequence_number),str(icmp_originate_timestamp),str(icmp_receive_timestamp),str(icmp_transmit_timestamp),str(icmpdata)]], columns= ['Date','Size','Version','Header Length','Type of Service','Length','hex ID','str ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','type','code','checksum','identifier','sequence number','originate timestamp','receive timestamp','transmit timestamp','data'])
    #the data is: the identifier the sequence number + the adress mask + ICMP header + 8 first bits of data
    elif icmp_type == 17 or icmp_type == 18:
        icmp_unpacked_data = struct.unpack('!HHL' , icmp_raw_data[:8])
        icmp_identifier = icmp_unpacked_data[0]
        icmp_sequence_number = icmp_unpacked_data[1]
        icmp_address_mask = icmp_unpacked_data[2]
        icmpdata = ''.join(chr(i) for i in icmp_raw_data[8:])
        icmpcsv = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)),str((ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(icmp_type),str(icmp_code),str(icmp_checksum),str(icmp_identifier),str(icmp_sequence_number),str(icmp_address_mask),str(icmpdata)]], columns= ['Date','Size','Version','Header Length','Type of Service','Length','hex ID','str ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','type','code','checksum','identifier','sequence number','address mask','data'])
    #the data is: the next-hop MTU + ICMP header + 8 first bits of data
    elif icmp_type == 3:
        icmp_unpacked_data = struct.unpack('!HH' , icmp_raw_data[:4])
        icmp_next_hop = icmp_unpacked_data[1]
        icmpdata = ''.join(chr(i) for i in icmp_raw_data[4:])
        icmpcsv = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)),str((ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(icmp_type),str(icmp_code),str(icmp_checksum),str(icmp_next_hop),str(icmpdata)]], columns= ['Date','Size','Version','Header Length','Type of Service','Length','hex ID','str ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','type','code','checksum','Next-hop MTU','data'])
    #in case of error
    else:
        icmpdata = ''.join(chr(i) for i in icmp_raw_data)
        icmpcsv = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)),str((ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(icmp_type),str(icmp_code),str(icmp_checksum),str(icmpdata)]], columns= ['Date','Size','Version','Header Length','Type of Service','Length','hex ID','str ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','type','code','checksum','data'])

#get TCP flags: 6 bits
def gettcpflags(n):
        missing = 18 - len(bin(n))
        count = 0
        tcpflags = ""
        for x in bin(n):
            if count ==12 - missing:
                flag = ' urg: ' + x + ','
                tcpflags = tcpflags + str(flag)
            if count ==13 - missing:
                flag = ' ack: ' + x + ','
                tcpflags = tcpflags + str(flag)
            if count ==14 - missing:
                flag = ' psh: ' + x + ','
                tcpflags = tcpflags + str(flag)
            if count ==15 - missing:
                flag = ' rst: ' + x + ','
                tcpflags = tcpflags + str(flag)
            if count ==16 - missing:
                flag = ' syn: ' + x + ','
                tcpflags = tcpflags + str(flag)
            if count ==17 - missing:
                flag = ' fin: ' + x + ','
                tcpflags = tcpflags + str(flag)
            if count >= 12 - missing:
                #print(flag)
                pass
            count = count + 1
        return tcpflags

#translate playload from IPv4 packet
def dataprocess(data):
    if protocolNr == 6: 		#TCP
        #unpack everything
        unpacked_TCP_data = struct.unpack('!HHLLHHHH' , data[:20])

        source_port = unpacked_TCP_data[0]
        destination_port = unpacked_TCP_data[1]
        sequence_number = unpacked_TCP_data[2]
        aquitment_number = unpacked_TCP_data[3]
        data_offset = unpacked_TCP_data[4] >> 12
        tcpflags = gettcpflags(unpacked_TCP_data[4])
        window = unpacked_TCP_data[5]
        sum_of_control = unpacked_TCP_data[6]
        pointeur = unpacked_TCP_data[7]
        options = data[20:]
        tcpdata = ''.join(chr(i) for i in data[24:])

        #register the TCP packet in a csv file
        print("TCP" + '\t\t' + str(data[20:]) +' \n' + str(tcpdata) + '\n')
        tcpcsv = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)),str((ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(source_port),str(destination_port),str(sequence_number),str(aquitment_number),str(tcpflags),str(window),str(sum_of_control),str(pointeur),str(options),str(tcpdata)]], columns= ['Date','Size','Version','Header Length','Type of Service','Length','hex ID','str ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','source port','destination port','sequence number','aquitment number','tcp flags','window','sum of control','pointer','options','data'])
        tcpcsv.to_csv(r'D:\programation\sniffer\tcp.csv', header=None, index=None, sep=',', mode='a')

    elif protocolNr == 17:		#UDP
        #unpack everything
        unpacked_UDP_data = struct.unpack('!HHHH' , data[:8])

        source_port = unpacked_UDP_data[0]
        destination_port = unpacked_UDP_data[1]
        udp_length = unpacked_UDP_data[2]
        udpchecksum = unpacked_UDP_data[3]
        udpdata = ''.join(chr(i) for i in data[8:])

        #register the UDP packet in a csv file
        print("UDP" + '\t\t' + str(data[8:]) +' \n'+str(udpdata) + '\n')
        udpcsv = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)),str((ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(source_port),str(destination_port),str(udp_length),str(udpchecksum),str(udpdata)]], columns= ['Date','Size','Version','Header Length','Type of Service','Length','hex ID','str ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','source port','destination port','udp length','checksum','data'])
        udpcsv.to_csv(r'D:\programation\sniffer\udp.csv', header=None, index=None, sep=',', mode='a')

    elif protocolNr == 1: 		#ICMP
    #unpack everything
        unpacked_ICMP_data = struct.unpack('!BBH' , data[:4])

        icmp_type = gettype(unpacked_ICMP_data[0])
        icmp_code = getcode(unpacked_ICMP_data[1])
        icmp_checksum = unpacked_ICMP_data[2]
        
        ##register the ICMP packet in a csv file
        translatedata(data[4:])
        print('ICMP captured')
        icmpcsv.to_csv(r'D:\programation\sniffer\icmp.csv', header=None, index=None, sep=',', mode='a')

    else:
        #in case of error
        processed_data = data
        
    
    return data 



 
# the public network interface
while(True):
	x = kbfunc() 

    #if we got a keyboard hit
	
	if x != False and x.decode() == 'x':
	    print ("STOPPING, KEY:", x.decode())
	    input("continue ??")


	else:
            HOST = gethostbyname(gethostname())
 
            # create a raw socket and bind it to the public interface
            s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
            s.bind((HOST, 0))
 	
            # Include IP headers
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            s.ioctl(SIO_RCVALL, RCVALL_ON)
            data = receiveData(s)
            # get the IP header (the first 20 bytes) and unpack them
            unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])
            version_IHL = unpackedData[0]
            version = version_IHL >> 4                  # version of the IP
            IHL = version_IHL & 0xF                     # internet header length
            TOS = unpackedData[1]                       # type of service
            totalLength = unpackedData[2]
            ID = unpackedData[3]                        # identification
            flags = unpackedData[4]
            fragmentOffset = unpackedData[4] & 0x1FFF	# packet number 
            TTL = unpackedData[5]                       # time to live
            protocolNr = unpackedData[6]  				# TCP, UDP or ICMP
            protocol = getProtocol(protocolNr)
            checksum = unpackedData[7]
            sourceAddress = inet_ntoa(unpackedData[8])
            destinationAddress = inet_ntoa(unpackedData[9])
            time = datetime.datetime.now()
            processed_data = dataprocess(data[20:])
            translated_data = ''.join(chr(i) for i in data[20:]) 

            df = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(data),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)+ str(ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(data[20:])]], columns= ['Date','Size','Raw Data','Version','Header Length','Type of Service','Length','ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','Playload'])
            dataframe = pd.DataFrame([[str(time.strftime("%c")),translated_data]], columns= ['Date','data'])
            final = pd.DataFrame([[str(time.strftime("%c")),str(unpackedData[2]),str(version),str(IHL*4),str(getTOS(TOS)),str(totalLength),str(hex(ID)),str((ID)),str(getFlags(flags)),str(fragmentOffset),str(TTL),str(protocol),str(checksum),str(sourceAddress),str(destinationAddress),str(translated_data)]], columns= ['Date','Size','Version','Header Length','Type of Service','Length','hex ID','str ID','Flags','Fragment','TTL','Protocol','Checksum','Source','Destination','data'])
    
            #save as csv
            df.to_csv(r'D:\programation\sniffer\pandas.csv', header=None, index=None, sep=',', mode='a')
            dataframe.to_csv(r'D:\programation\sniffer\logs.txt', header=None, index=None, sep='\n', mode='a')
            final.to_csv(r'D:\programation\sniffer\webdata.csv', header=None, index=None, sep=',', mode='a')
