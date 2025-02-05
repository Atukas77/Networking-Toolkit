This Python-based network application suite implements several fundamental networking tools, including ping, single-threaded and multithreaded traceroute utility and a web proxy server. The project is designed to enhance practical understanding of network sockets, ICMP/UDP-based networking, and HTTP proxies. It is intended to replicate built-in terminal networking commands.

Features:  

ICMP Ping (ping):  
Sends ICMP echo request packets to a target.  
Measures round-trip time (RTT) for each response.  
Works similarly to the Linux ping command.  

Single-Threaded Traceroute (traceroute):  
Uses UDP or ICMP probes to trace the network path to a destination.  
Sends packets with increasing Time-To-Live (TTL) to discover intermediate network hops.  

Multithreaded Traceroute (mtroute):  
Uses ICMP packets to measure RTT for each hop.  
Runs in parallel using Python threading, sending packets and receiving responses simultaneously.  
Can be used to analyze network delays and intermediate nodes between a source and destination.  

Web Proxy (proxy):  
Intercepts HTTP requests and forwards them to web servers.  
Implements basic caching to store previously requested web pages.  
Supports configurable port binding.  

Cloning the repository:  
git clone https://github.com/Atukas77/Networking-Toolkit.git  
cd Networking-Toolkit  

Prerequisites:

Python 3  
curl (for testing the proxy)

Running the Application:

Note: Some commands, especially those using ICMP packets, may require root (sudo) privileges. If you encounter permission errors, try running them with sudo.

Navigate to the project directory and run:  
python3 NetworkingToolkit.py --help  
This will display usage information for all available commands.  

Usage examples:

Running the ICMP Ping  
sudo python3 NetworkingToolkit.py ping google.com

Running the Single-Threaded Traceroute  
sudo python3 NetworkingToolkit.py traceroute -p udp google.com   
-p udp uses UDP packets.  
-p icmp uses ICMP packets.  

Running the ICMP Multithreaded Traceroute  
sudo python3 NetworkingToolkit.py mtroute -p icmp google.com 

Running the Web Proxy  
python3 NetworkingToolkit.py proxy -p 8000  
(Starts the web proxy on port 8000)  
To test it (in a different terminal window):  
curl http://example.com --proxy 127.0.0.1:8000  

