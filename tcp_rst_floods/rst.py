import os

def reset():
    interface = input("interface ? ")
    ip = input("ip addr ? ")
    c = input("count ? ")
    p = os.popen("rstconn -i {iface} --server-ip {ip1} --server-port 502 --packet-count {co}".format(iface=interface, ip1=ip, co=c))
    
try:
    reset()
except KeyboardInterrupt:
    exit()