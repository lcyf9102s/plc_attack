import os

def reset():
    interface = input("interface ? ")
    ip = input("ip addr ? ")
    c = input("count ? ")
    while True:
        p = os.popen("rstconn -i {iface} --server-ip {ip1} --server-port 502 --packet-count {co}".format(iface=interface, ip1=ip, co=c))
        out = p.read()
        p.close()
        print(out)
    
try:
    reset()
except KeyboardInterrupt:
    exit()