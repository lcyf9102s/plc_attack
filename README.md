# plc_attack
一些自制的plc、hmi攻击脚本


NetfilterQueue版本的基本上是终极版本了，利用iptables将mitm攻击接收到的数据包连接到用户空间（nfqueue），再利用NetfilterQueue通过该连接来访问Linux内核中的数据，可以使用scapy对数据包进行修改后再发出，实现真正意义上的mitm攻击篡改数据，同时也提高了攻击的隐蔽性和成功率。

note.
先前使用scapy socket或是modbus_tk发送修改数据会直接暴露攻击设备的IP地址，使用scapy伪造源IP地址三次握手建立tcp连接后再发送modbus请求的方式在虚拟机中测试成功，但是有较大的问题，因为在绝大多数系统中，tcp连接都是通过内核（kernel）建立的，scapy是用户空间（userspace）的软件，因而当scapy对另一设备发送SYN包，该设备回应一个SYN,ACK包，发送设备接收到SA包后发现自己的内核并没有发起一个tcp连接，于是发送一个RST包重置连接（connection reset），对面设备接收到RST包后就会使tcp连接中断。如果modbus请求没有在rst包之前到达，就无法实现数据篡改。在虚拟机测试中，从站系统为win 7，使用modbus slave模拟，主站为ubuntu 20.04 lts，使用modbus_tk模拟modbus请求，中间人攻击设备为kali Linux。在测试中modbus请求基本上能在rst包到达win 7之前到达从站，后使用相同代码在实体设备上（信捷plc、威纶触摸屏）测试，scapy发出第一个SYN包的同时，触摸屏就发出一个rst包，连接立刻被重置，几乎无法建立tcp连接。也考虑过使用iptables拦截rst包，但是效果不理想。



> TO DO (2023.1.5)
> 用rust或c++改写，优化性能。
> Update: 尝试使用Google Jules以C++完全改写，见branch: cpp-modbus-mitm. 未测试，效果未知。
