import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback
import threading

UDP_CODE = socket.IPPROTO_UDP
ICMP_ECHO_REQUEST = 8
MAX_DATA_RECV = 65535
MAX_TTL = 30

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.231.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='udp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_m = subparsers.add_parser('mtroute', aliases=['mt'],
                                         help='run traceroute')
        parser_m.set_defaults(timeout=2, protocol='udp')
        parser_m.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_m.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_m.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_m.set_defaults(func=MultiThreadedTraceRoute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args()

        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: bytes) -> int: 
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    # Print Ping output
    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, host, numPacketsTransmitted, rtts):
        if len(rtts) > 0:
            print(f'--- {host} ping statistics ---')
            lossPercent = int((100.0 - 100.0*(len(rtts)/numPacketsTransmitted)))
            print(f'{numPacketsTransmitted} packets transmitted, {len(rtts)} received, {lossPercent}% packet loss')
            avgRTT = sum(rtts) / len(rtts)
            deviations = [abs(rtt - avgRTT) for rtt in rtts]
            mdev = sum(deviations) / len(deviations)
            minRTT = min(rtts)
            maxRTT = max(rtts)
            print("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms" % (1000*minRTT, 1000*avgRTT, 1000*maxRTT, 1000*mdev))

    # Print one line of traceroute output
    def printMultipleResults(self, ttl: int, pkt_keys: list, hop_addrs: dict, rtts: dict, destinationHostname = ''):
         # no responses for this ttl
        if pkt_keys is None:
            print(str(ttl) + '* * *')
            return

        # Sort packet keys (sequence numbers or UDP ports)
        pkt_keys = sorted(pkt_keys)
        output = str(ttl) + ' '
        hop_addr = None
        hostName = None

        # first check if we have any responses for this TTL
        for pkt_key in pkt_keys:
            if pkt_key in hop_addrs:
                hop_addr = hop_addrs[pkt_key]
                break

        if hop_addr is not None:
            #get the hostname for the hop
            try:
                hostName = socket.gethostbyaddr(hop_addr)[0]
                output += hostName + ' (' + hop_addr + ') '
            except socket.herror:
                output += hop_addr + ' (' + hop_addr + ') '
        else:
            # no responses for this TTL
            output += '* * *'
            print(output)
            return

        # for each probe print rtt or *
        for pkt_key in pkt_keys:
            if pkt_key in rtts:
                rtt = rtts[pkt_key]
                output += str(round(1000 * rtt, 3)) + ' ms '
            else:
                output += '* '

        print(output)                   

class ICMPPing(NetworkApplication):
    
    def __init__(self, args):
        host = None
        # Look up hostname, resolving it to an IP address
        try:
            host = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return

        print('Ping to: %s (%s)...' % (args.hostname, host))

        # Create an ICMP socket 
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # Send ping probes and collect responses 
        numPings = args.count
        seq_num = 0
        numPingsSent = numPings
        rtts = [] 
        while(numPings > 0):

            # Do one ping approximately every second
            rtt, ttl, packetSize, seq = self.doOnePing(host, args.timeout, seq_num)

            # Print out the RTT (and other relevant details) using the printOneResult method
            if rtt is not None:
                self.printOneResult(host, packetSize, rtt*1000, seq, ttl) 
                rtts.append(rtt)

            # Sleep for a second
            time.sleep(1) 

            # Update sequence number and number of pings
            seq_num += 1
            numPings -= 1

        # Print loss and RTT statistics (average, max, min, etc.)
        self.printAdditionalDetails(args.hostname, numPingsSent, rtts)
        
        # Close ICMP socket
        self.icmpSocket.close()

    # Receive Echo ping reply
    def receiveOnePing(self, destinationAddress, packetID, sequenceNumSent, timeout):
        
        # Wait for the socket to receive a reply
        echoReplyPacket = None
        isTimedout = False
        try:
            echoReplyPacket, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
        except socket.timeout as e:
            isTimedout = True

        # Once received, record time of receipt, otherwise, handle a timeout
        timeRecvd = time.time()
        if isTimedout: # timeout
            return None, None, None, None

        # Extract the IP header: 
        ip_header = echoReplyPacket[:20]
        version_ihl, tos, total_length, identification, flags_offset, ttl, proto, checksum, src_ip, dest_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # Read the IP Header Length (using bit masking) 
        ip_header_len_field = (version_ihl & 0x0F)

        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4

        payloadSize = total_length - ip_header_len      
        icmpHeader = echoReplyPacket[ip_header_len:ip_header_len + 8]
        icmpType, code, checksum, p_id, sequenceNumReceived = struct.unpack('!BBHHH', icmpHeader)

        # Check that the ID and sequence numbers match between the request and reply
        if packetID != p_id or sequenceNumReceived != sequenceNumSent:
            return None, None, None, None

        # Return the time of Receipt
        return timeRecvd, ttl, payloadSize, sequenceNumReceived

    # Send Echo Ping Request
    def sendOnePing(self, destinationAddress, packetID, sequenceNr, ttl=None, dataLength=0):
        # Build ICMP header
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, packetID, sequenceNr)
        
        # Checksum ICMP packet using given function
        # include some bytes 'AAA...' in the data (payload) of ping
        data = str.encode(dataLength * 'A')
        my_checksum = self.checksum(header+data)

        # Insert checksum into packet
        packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packetID, sequenceNr)

        if ttl is not None:
            self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # Send packet using socket
        self.icmpSocket.sendto(packet+data, (destinationAddress, 1))

        # Record time of sending (state)
        timeSent = time.time()
        return timeSent

    def doOnePing(self, destinationAddress, timeout, seq_num):

        # Call sendOnePing function
        packetID = random.randint(1, 65535)
        timeSent = self.sendOnePing(destinationAddress, packetID, seq_num, dataLength=48)

        # Call receiveOnePing function
        timeReceipt, ttl, packetSize, seq = self.receiveOnePing(destinationAddress, packetID, seq_num, timeout)

        # Compute RTT
        rtt = None
        if timeReceipt is None:
            print("Error receiveOnePing() has timed out")
        else:
            rtt = timeReceipt - timeSent

        # 6. Return total network delay, ttl, size and sequence number
        return rtt, ttl, packetSize, seq

class Traceroute(ICMPPing):

    def __init__(self, args):
        args.protocol = args.protocol.lower()

        # Look up hostname, resolving it to an IP address
        self.dstAddress = None
        try:
            self.dstAddress = socket.gethostbyname(args.hostname)
            socket.getaddrinfo(args.hostname, None, socket.AF_INET6)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return
        print('%s traceroute to: %s (%s) ...' % (args.protocol, args.hostname, self.dstAddress))

        # Initialise instance variables
        self.isDestinationReached = False
        self.timeouts_in_a_row = 0 # variable added to handle consecutive timeouts
        # generate random 16bit packetID from 0 to 2^16 - 1
        self.packetID = random.randint(0, 65535)
        # Create a raw socket bound to ICMP protocol
        self.icmpSocket = None
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # Run traceroute
        self.runTraceroute()

        # Close ICMP socket
        self.icmpSocket.close()

    def runTraceroute(self):

        hopAddr = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        ttl = 1

        while(ttl <= MAX_TTL and self.isDestinationReached == False):
            if args.protocol == "icmp":
                self.sendIcmpProbesAndCollectResponses(ttl)

            elif args.protocol == "udp":
                self.sendUdpProbesAndCollectResponses(ttl)
            else:
                print(f"Error: invalid protocol {args.protocol}. Use udp or icmp")
                sys.exit(1)
            ttl += 1


    #send 3 ICMP traceroute probes per TTL and collect responses
    def sendIcmpProbesAndCollectResponses(self, ttl):
 
        hopAddr = None
        icmpType = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        max_timeouts = 6 # set for desired timeout tolerance
        response_received = False

        for sequenceNr in range(3):
            # Send one icmp traceroute probe
            packetID = self.packetID
            timeSent = self.sendOnePing(self.dstAddress, packetID, sequenceNr, ttl, 0)

            # Record a unique key (icmp sequencNr) associated with the probe
            pkt_keys.append(sequenceNr)

           # Receive the response (if one arrives within the timeout)
            trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
            if trReplyPacket is None:
                # Nothing is received within the timeout period
                continue
            
            # Extract sequence number and icmp type from the reply
            sequenceNrReceived, icmpType, packetIDReceived = self.parseICMPTracerouteResponse(trReplyPacket)

            #check that the received sequenceNr and packedID match
            if sequenceNrReceived != sequenceNr or packetIDReceived != self.packetID:
                continue
                
            # Check if we reached the destination
            if self.dstAddress == hopAddr and icmpType == 0:
                self.isDestinationReached = True

            # If the response matches the request, record the rtt and the hop address
            if timeRecvd is not None:
                rtts[sequenceNr] = timeRecvd - timeSent
                hop_addrs[sequenceNr] = hopAddr
                response_received = True

        #check consecutive timeouts
        if not response_received:
            self.timeouts_in_a_row += 1
        else:
            self.timeouts_in_a_row = 0 

        # Print the results
        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, self.dstAddress)
        #check if we should stop due to consecutive timeouts
        if self.timeouts_in_a_row >= max_timeouts:
            print("Traceroute terminated: did not receive response from destination.")
            self.isDestinationReached = True

    # Send 3 UDP traceroute probes per TTL and collect responses
    def sendUdpProbesAndCollectResponses(self, ttl):
        
        hopAddr = None
        icmpType = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        numBytes = 52
        dstPort = 33439
        max_timeouts = 6 # set for desired timeout tolerance
        response_received = False

        for _ in range(3): 
            # Send one UDP traceroute probe
            dstPort += 1
            timeSent = self.sendOneUdpProbe(self.dstAddress, dstPort , ttl, numBytes)

            # Record a unique key (UDP destination port) associated with the probe
            pkt_keys.append(dstPort)

            # Receive the response (if one arrives within the timeout)
            trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
            if trReplyPacket is None:
                # Nothing is received within the timeout period
                continue
            
            # Extract destination port from the reply
            dstPortReceived, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)
        
            # Check if we reached the destination
            if self.dstAddress == hopAddr and icmpType == 3:
                self.isDestinationReached = True
            # If the response matches the request, record the rtt and the hop address
            if dstPort == dstPortReceived:
                rtts[dstPort] = timeRecvd - timeSent
                hop_addrs[dstPort] = hopAddr
                response_received = True

        #check consecutive timeouts
        if response_received == False:
            self.timeouts_in_a_row += 1
        else:
            self.timeouts_in_a_row = 0 

        # Print one line of the results for the 3 probes
        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname)

        #check if we should stop due to consecutive timeouts
        if self.timeouts_in_a_row >= max_timeouts:
            print("Traceroute terminated: did not receive response from destination.")
            self.isDestinationReached = True

    # Parse the response to UDP probe 
    def parseUDPTracerouteResponse(self, trReplyPacket):

        # Parse the IP header
        dst_port = None
        # Extract the first 20 bytes 
        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])

        # Read the IP Header Length (using bit masking) 
        ip_header_len_field = (ip_header[0] & 0x0F)

        # Compute the IP header length
        ip_header_len = ip_header_len_field * 4
        
        # Parse the outermost ICMP header which is 8 bytes long:
        icmpType, _, _, _, _  = struct.unpack("!BBHHH", trReplyPacket[ip_header_len:ip_header_len + 8])
        
        # Parse the ICMP message if it has the expected type
        if icmpType == 3 or icmpType == 11:
            ip_header_inner = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[ip_header_len + 8:ip_header_len+28])

            # This is the original IP header sent in the probe packet
            # It should be 20 bytes, but let's not assume anything and extract the length
            # of the header
            ip_header_len_field = (ip_header_inner[0] & 0x0F)
            ip_header_inner_len = ip_header_len_field * 4
            
            # Extract the destination port and match using source port (UDP)
            _, dst_port, _, _ = struct.unpack('!HHHH', trReplyPacket[ip_header_len + 8 + ip_header_inner_len : ip_header_len + 8 + ip_header_inner_len + 8])

        return dst_port, icmpType
    
    # Parse the response to the ICMP probe
    def parseICMPTracerouteResponse(self, trReplyPacket):
        
         # Parse the IP header
        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])
        # Read the IP Header Length (using bit masking) 
        ip_header_len_field = (ip_header[0] & 0x0F)
        # Compute the IP header length
        ip_header_len = ip_header_len_field * 4

        # Parse the outermost ICMP header which is 8 bytes long:
        icmp_header = trReplyPacket[ip_header_len:ip_header_len+8]
        icmph = struct.unpack("!BBHHH", icmp_header)
        icmpType = icmph[0]
        icmpType, _, _, packetIDReceived, sequenceNr = struct.unpack("!BBHHH", icmp_header)
        # Parse the ICMP message if it has the expected type
        if icmpType == 0:  # echo Reply
            return sequenceNr, icmpType, packetIDReceived
        elif icmpType == 11:  #time exceeded
            #calculate the offset where the icmp payload starts
            icmp_payload_offset = ip_header_len + 8
            # extract the original ip header from the icmp payload
            original_ip_header = trReplyPacket[icmp_payload_offset:icmp_payload_offset + 20]
            original_ip_header_len = (original_ip_header[0] & 0x0F) * 4
            # calculate offset where the original icmp header starts
            original_icmp_header_offset = icmp_payload_offset + original_ip_header_len
            # extract the original icmp header and unpack
            original_icmp_header = trReplyPacket[original_icmp_header_offset:original_icmp_header_offset + 8]
            _, _, _, packetIDReceived, sequenceNr = struct.unpack("!BBHHH", original_icmp_header)

            return sequenceNr, icmpType, packetIDReceived
        else:
            return None, None, None
    
    def receiveOneTraceRouteResponse(self):

        timeReceipt = None
        hopAddr = None
        pkt = None

        # Receive one packet or timeout
        try:
            pkt, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
            timeReceipt = time.time()
            hopAddr = addr[0]
        
        # Handler for timeout on receive
        except socket.timeout as e:
            timeReceipt = None

        # Return the packet, hop address and the time of receipt
        return pkt, hopAddr, timeReceipt

    def sendOneUdpProbe(self, destAddress, port, ttl, dataLength):

        # Create a UDP socket
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP_CODE)

        # Use a socket option to set the TTL in the IP header
        udpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # Send the UDP traceroute probe
        udpSocket.sendto(str.encode(dataLength * '0'), (destAddress, port))

        # Record the time of sending
        timeSent = time.time()

        # Close the UDP socket
        udpSocket.close()

        return timeSent

class MultiThreadedTraceRoute(Traceroute):

    def runTraceroute(self):
        pass  #do nothing to prevent parent class traceroute from running

    def __init__(self, args):
        
        # Initialise instance variables (add others if needed)
        args.protocol = args.protocol.lower()
        self.timeout = args.timeout
        
        #check hostname
        try:
            host = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return
        
        super().__init__(args) #use inherited initializer

        # recreate icmp socket since parent class closed it
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # Set the timeout on the socket
        self.icmpSocket.settimeout(self.timeout)

        self.send_complete = threading.Event() #shared event to signal when sending is complete

        #shared variables
        self.isDestinationReached = False
        self.hop_addrs = dict()
        self.rtts = dict()
        self.sendTimes = dict() # stores the time sent for each probe
        self.timeouts_in_a_row = 0 
        self.max_timeouts = 4 # set for desired timeout tolerance
        self.response_received = False
        #lock for accessing data shared between the two threads
        self.lock = threading.Lock()  

        # Create a thread to send probes
        self.send_thread = threading.Thread(target=self.send_probes)

        # Create a thread to receive responses 
        self.recv_thread = threading.Thread(target=self.receive_responses)

        # Start the threads
        self.send_thread.start()
        self.recv_thread.start()

        # Wait until both threads are finished executing
        self.send_thread.join()
        self.recv_thread.join()

        # Close the ICMP socket
        self.icmpSocket.close()

        # Print results
        self.print_results()
        
            
    def send_probes(self):

        ttl = 1 
        while ttl <= MAX_TTL and self.isDestinationReached == False:

            # Send three probes per TTL
            for sequenceNr in range(3):  
                if args.protocol == "icmp":
                    # send one icmp traceroute probe (reusing sendOnePing)
                    packetID = ttl
                    timeSent = self.sendOnePing(self.dstAddress, packetID, sequenceNr, ttl, 0)     
                    
                    # save timeSent in the shared dictionary
                    self.lock.acquire()
                    try:  # a tuple of sequenceNr and ttl acts as a unique key for each probe sent
                        self.sendTimes[(sequenceNr, ttl)] = timeSent
                        
                    finally:
                        self.lock.release()

                elif args.protocol == "udp":
                    pass # UDP multithreaded traceroute to be implemented
                         # single threaded version available       

                # Sleep for a short period between sending probes
                time.sleep(0.05)  # Small delay between probes

            if self.isDestinationReached == False:
                ttl += 1
            else:
                break


        # A final sleep before notifying the receive thread to exit
        time.sleep(args.timeout)
        # Notify the other thread that sending is complete
        self.send_complete.set()
               

    def receive_responses(self):
        # flag and counter to track when the first probe reaches the destination
        # created to break out of the loop in case sendTimes dict is still not empty
        first_probe_reached_destination = False
        destination_probes_reached = 0

        #Keep receiving responses until notified by the other thread or sendTimes not empty -
        #there might be probes whose responses have not been received yet
        while not self.send_complete.is_set() or self.sendTimes:
            if first_probe_reached_destination == True:
                destination_probes_reached += 1
            if destination_probes_reached == 3:
                self.sendTimes = None
                # break when all three probes have been sent to destination (not necessarily received a response)
                break 

            if args.protocol == "icmp":
                try:
                    #receive packet or handle a timeout
                    trReplyPacket, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
                    timeReceipt = time.time()
                    hopAddr = addr[0]

                    #parse the received packet reusing the parse method
                    sequenceNr, icmpType, packetIDReceived = self.parseICMPTracerouteResponse(trReplyPacket)
                    if sequenceNr is not None:
                        self.lock.acquire()
                        key = (sequenceNr, packetIDReceived)  # use (sequenceNr, ttl) as key
                        try:
                            if key in self.sendTimes:
                                ttl = packetIDReceived  # since packetID was set to ttl
                                # save rtts and addresses to print later 
                                if ttl not in self.hop_addrs:
                                    self.hop_addrs[ttl] = dict()
                                if ttl not in self.rtts:
                                    self.rtts[ttl] = dict()
                                self.hop_addrs[ttl][sequenceNr] = hopAddr
                                self.rtts[ttl][sequenceNr] = timeReceipt - self.sendTimes[key]

                        finally:
                            self.lock.release()
                            
                        # reset  timeouts counter
                        self.timeouts_in_a_row = 0
                        #check if destination reached
                        if icmpType == 0 and hopAddr == self.dstAddress:
                            first_probe_reached_destination = True
                            self.isDestinationReached = True
                            self.send_complete.set()

                except socket.timeout:
                    # increment timeouts counter
                    self.lock.acquire()
                    try:
                        self.timeouts_in_a_row += 1
                        
                    finally:
                        self.lock.release()

                    # check if maximum consecutive timeouts have been reached
                    if self.timeouts_in_a_row >= self.max_timeouts:
                        self.isDestinationReached = True
                        self.send_complete.set()
                        break
                    continue  #continue listening
                    
            elif args.protocol == "udp":
                pass # UDP traceroute to be implemented     


    # print results after both sending and receiving threads are finished
    def print_results(self):
        #iterate from 1 until max ttl
        for ttl in range(1, (max(self.hop_addrs.keys(), default=0) + 1)):
            if ttl in self.hop_addrs:
                #data to be passed into printing method
                pkt_keys = [0, 1, 2]
                hop_addrs = self.hop_addrs[ttl]
                rtts = self.rtts[ttl]
                # reuse printMultipleResults method
                self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, self.dstAddress)
            else:
                #no responses for this ttl
                print(f"{ttl} * * *")
        if self.timeouts_in_a_row >= self.max_timeouts:
            print("Traceroute terminated: did not receive response from destination.")

# A basic multi-threaded web server implementation
class WebServer(NetworkApplication):

    def __init__(self, args):
        print('Web Server starting on port: %i...' % args.port)
        
        # Create a TCP socket 
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Bind the TCP socket to server address and server port
        serverSocket.bind(("", args.port))
        
        # Continuously listen for connections to server socket
        serverSocket.listen(100)
        print("Server listening on port", args.port)
        
        while True:
            # Accept incoming connections
            connectionSocket, addr = serverSocket.accept()
            print(f"Connection established with {addr}")
            
            # Create a new thread to handle each client request
            threading.Thread(target=self.handleRequest, args=(connectionSocket,)).start()

        # Close server socket (this would only happen if the loop was broken, which it isn't in this example)
        serverSocket.close()

    def handleRequest(self, connectionSocket):
        try:
            # Receive request message from the client
            message = connectionSocket.recv(MAX_DATA_RECV).decode()

            # Extract the path of the requested object from the message (second part of the HTTP header)
            filename = message.split()[1]

            # Read the corresponding file from disk
            with open(filename[1:], 'r') as f:  # Skip the leading '/'
                content = f.read()

            # Create the HTTP response
            response = 'HTTP/1.1 200 OK\r\n\r\n'
            response += content

            # Send the content of the file to the socket
            connectionSocket.send(response.encode())

        except IOError:
            # Handle file not found error
            error_response = "HTTP/1.1 404 Not Found\r\n\r\n"
            error_response += "<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n"
            connectionSocket.send(error_response.encode())

        except Exception as e:
            print(f"Error handling request: {e}")

        finally:
            # Close the connection socket
            connectionSocket.close()

class Proxy(NetworkApplication):

    # __init__ based on the WebServer class __init__
    def __init__(self, args):
        # cache directory
        self.cache_dir = "./proxy_cache"
        os.makedirs(self.cache_dir, exist_ok=True)  # create cache directory if not yet there
        self.cache_log = dict()  # dict to map URLs to cache file paths
        print('Web Proxy starting on port: %i...' % (args.port))
        
        # lock for cache access
        self.cache_lock = threading.Lock()

        # create a TCP client socket       
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the TCP socket to client address and client port
        self.serverSocket.bind(("", args.port))

        # Continuously listen for connections to server socket
        self.serverSocket.listen(100)
        print(f"Proxy listening on port", args.port)

        while True:
            try:
                # accept incoming connections
                connectionSocket, addr = self.serverSocket.accept()
                print(f"Connection established with {addr}")
                
                # Create a new thread to handle each client request
                threading.Thread(target=self.handleRequest, args=(connectionSocket,)).start()

            # keyboard interrupt handling to terminate neatly
            except KeyboardInterrupt:
                    print("\nKeyboard interrupt. Web proxy terminated.")
                    self.serverSocket.close()
                    exit()
                    break
            
        self.serverSocket.close()

    def handleRequest(self, clientSocket):
        try:
            # Receive request message from the client
            message = clientSocket.recv(MAX_DATA_RECV).decode()
            print("Received request:", message)
            # break down the request message
            request_lines = message.splitlines()
            if request_lines:
                request_line = request_lines[0]
            else:
                request_line = ""

            if request_line:
                method, path, http_version = request_line.split() # version unnecessary for now
            else:
                method, path, http_version = ("", "", "")
            
            # check if method is valid
            if method.upper() != "GET":
                print(f"{method} method not supported, only GET is supported for this proxy.")
                clientSocket.close()
                return
            
            host = ""
            for line in request_lines[1:]:#skip the request line
                if line.lower().startswith("host:"):
                    host = line.split(":")[1].strip()
                    break

            if not host:
                print("Found no host header in the request.")
                clientSocket.close()
                return
            
            # check the cache
            cache_key = f'{host}{path}'
            cache_filename = self.url_hash(cache_key) # generate filename
            with self.cache_lock:
                if cache_key in self.cache_log:
                    # if cache hit, serve directly from cache
                    print(f"Cache hit. Serving from cache.\n")
                    cache_path = self.cache_log[cache_key]
                    with open(cache_path, 'rb') as cache_file: #binary read mode
                        clientSocket.sendall(cache_file.read())

                else:
                    # if cache miss, fetch from server and forward
                    print(f"Cache miss. Fetching from server.\n")
                    # conect to server
                    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                    serverSocket.connect((host, 80)) #socket to target server
                    serverSocket.sendall(message.encode()) # forward the request to the server
                    
                    # store response in a new cache file
                    cache_path = os.path.join(self.cache_dir, cache_filename)
                    with open(cache_path, 'wb') as cache_file: #binary write mode
                        # receive the response from server
                        while True:
                            response = serverSocket.recv(MAX_DATA_RECV)
                            if len(response) > 0: 
                                clientSocket.sendall(response) # forward the server response back to client
                                cache_file.write(response)  # write to cache
                                cache_file.flush()
                                self.cache_log[cache_key] = cache_path # update cache log dict
                            else:
                                break
                    
                    serverSocket.close() # close target server socket

        except Exception as e:
            print(f"Error handling request: {e}")
        
        finally:
            # close the client connection socket
            clientSocket.close()

    def url_hash(self, url):
        # generate unique numeric hash by summing char ascii codes multiplied by position
        hash =  sum(ord(c) * i for i, c in enumerate(url, start=1)) % 99999999 #modulo to limit length
        return str(hash) #return as string



if __name__ == "__main__":
        
    args = setupArgumentParser()
    args.func(args)
