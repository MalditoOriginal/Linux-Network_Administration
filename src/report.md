## Part 1. ipcalc tool ##

**== Task ==**

### 1.1. Networks and Masks ###

**Define and write in the report:**

**1. Network address of 192.167.38.54/13**

`$ ipcalc 192.167.38.54/13`

    Address: 192.160.0.0

![linux](src/images/Part_1/linux1.1-1.png)

**2. Conversion of the mask 255.255.255.0 to prefix and binary, /15 to normal and binary, 11111111.11111111.11111111.11110000 to normal and prefix**

a. Conversion of the mask 255.255.255.0 to prefix and binary:

>The prefix notation - 255.255.255.0

>Binary - 11111111.11111111.11111111.00000000

b. Conversion of /15 to normal and binary:

>The normal notation - 255.254.0.0
>The binary - 11111111.11111110.00000000.00000000

c. Conversion of 11111111.11111111.11111111.11110000 to normal and prefix:

`$ ipcalc 11111111.11111111.11111111.11110000`

>The normal notation - 255.255.255.240
>The prefix notation - /28

3. Minimum and maximum host in 12.167.38.4 network with masks: /8, 11111111.11111111.00000000.00000000, 255.255.254.0 and /4

a. Mask /8

`$ ipcalc 12.167.38.4/8`

![linux](src/images/Part_1/linux1.1-3a.png)

    HostMin:   12.0.0.1             00001100. 00000000.00000000.00000001
    HostMax:   12.255.255.254       00001100. 11111111.11111111.11111110

b. Mask 11111111.11111111.00000000.00000000 (/16)

`$ ipcalc 12.167.38.4/16`

![linux](src/images/Part_1/linux1.1-3b.png)

    HostMin:   12.167.0.1           00001100.10100111. 00000000.00000001
    HostMax:   12.167.255.254       00001100.10100111. 11111111.11111110

c. Mask 255.255.254.0 (/23)

`$ ipcalc 12.167.38.4/255.255.254.0`

![linux](src/images/Part_1/linux1.1-3c.png)

    HostMin:   12.167.38.1          00001100.10100111.0010011 0.00000001
    HostMax:   12.167.39.254        00001100.10100111.0010011 1.11111110

d. Mask /4

`$ ipcalc 12.167.38.4/4`

![linux](src/images/Part_1/linux1.1-3d.png)

    HostMin:   0.0.0.1              0000 0000.00000000.00000000.00000001
    HostMax:   15.255.255.254       0000 1111.11111111.11111111.11111110

### 1.2. localhost ###

**Define and write in the report whether an application running on localhost can be accessed with the following IPs: 194.34.23.100, 127.0.0.2, 127.1.0.1, 128.0.0.1**


    Термин "localhost" относится к интерфейсу loopback устройства, обычно идентифицируемому IP-адресом 127.0.0.1. Он используется для тестирования сетевого подключения на локальной машине без участия внешней сети. Когда приложение привязано к адресу localhost, оно может быть доступно только из того же устройства.

>a. 194.34.23.100:
>IP-адрес 194.34.23.100 не соответствует адресу localhost. Это обычный IP-адрес, связанный с определенной сетью. Поэтому приложение, >работающее на localhost, не будет доступно через этот IP-адрес.

>b. 127.0.0.2:
>IP-адрес 127.0.0.2 находится в диапазоне адресов localhost. Приложение, >работающее на localhost, будет доступно через 127.0.0.2.

>c. 127.1.0.1:
>IP-адрес 127.1.0.1 также находится в диапазоне адресов localhost. В этом случае он попадает в допустимые IP-адреса интерфейса loopback (127.>0.0.1 - 127.255.255.254). Поэтому приложение, работающее на localhost, может быть доступно с использованием IP-адреса 127.1.0.1.

>d. 128.0.0.1:
>IP-адрес 128.0.0.1 не находится в диапазоне адресов localhost (127.x.x.x). Это обычный IP-адрес, который не относится к интерфейсу >loopback. Поэтому приложение, работающее на localhost, не будет доступно через этот IP-адрес.

### 1.3. Network ranges and segments ###

**Define and write in a report:**

1. Which of the listed IPs can be used as public and which only as private: 10.0.0.45, 134.43.0.2, 192.168.4.2, 172.20.250.4, 172.0.2.1, 192.172.0.1, 172.68.0.2, 172.16.255.255, 10.10.10.10, 192.169.168.1

    Приватные IP-адреса зарезервированы для внутренних сетей и не могут быть маршрутизируемыми через интернет. Они обычно используются в локальных сетях (например, домашних или офисных сетях) и не могут быть непосредственно доступными из интернета. С другой стороны, публичные IP-адреса являются глобально маршрутизируемыми и могут быть доступными из интернета.

>Диапазоны адресов, предназначенные для использования в частных сетях, следующие:

> - Класс A: 10.0.0.0 - 10.255.255.255
> - Класс B: 172.16.0.0 - 172.31.255.255
> - Класс C: 192.168.0.0 - 192.168.255.255

- Private IPs:
    - 10.0.0.45

    ![linux](src/images/Part_1/linux1.3-1.png)

    - 192.168.4.2

    ![linux](src/images/Part_1/linux1.3-3.png)

    - 172.20.250.4

    ![linux](src/images/Part_1/linux1.3-4.png)

     - 172.16.255.255

    ![linux](src/images/Part_1/linux1.3-7.png)

    - 10.10.10.10

    ![linux](src/images/Part_1/linux1.3-8.png)

- Public IPs:

    - 134.43.0.2:

    ![linux](src/images/Part_1/linux1.3-2.png)    

    - 192.172.0.1

    ![linux](src/images/Part_1/linux1.3-5.png)

    - 172.68.0.2

    ![linux](src/images/Part_1/linux1.3-6.png)

    - 192.169.168.1

    ![linux](src/images/Part_1/linux1.3-9.png)


2. Which of the listed gateway IP addresses are possible for 10.10.0.0/18 network: 10.0.0.1, 10.10.0.2, 10.10.10.10, 10.10.100.1, 10.10.1.255

    Сетевой адрес 10.10.0.0/18 представляет собой сеть с маской подсети 255.255.192.0. Это означает, что первые 18 бит в IP-адресе представляют сеть, а оставшиеся биты доступны для адресации узлов.

    IP-адрес шлюза должен находиться в той же сети, что и узлы, но не должен быть назначен конкретному узлу. Поэтому он должен иметь тот же сетевой адрес, что и узлы, но с нулевой или единичной частью хоста (сетевой или широковещательной адрес соответственно).

- IP addresses which are possible for 10.10.0.0/18 network:

    - 10.10.0.2; 10.10.10.10; 10.10.1.255

- IP addresses which are not possible for 10.10.0.0/18 network:

    - 10.0.0.1; 10.10.100.1

    ![linux](src/images/Part_1/linux1.3-10.png)
## Part 2. Static rounting between two machines ##

**== Task ==**

**Start two virtual machines (hereafter -- ws1 and ws2)**

View existing network interfaces with the `$ ip` a command

ws1:

![linux](src/images/Part_2/linux2.0-1.png)

ws2:

# This is the network config written by 'subiquity'
network:
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: false
      addresses: [172.24.116.8/12]
      routes:
        - to: 192.168.100.10
          via: 172.24.116.8
  version: 2

![linux](src/images/Part_2/linux2.0-2.png)

**Describe the network interface corresponding to the internal network on both machines and set the following addresses and masks: ws1 - 192.168.100.10, mask */16 *, ws2 - 172.24.116.8, mask /12**

_etc/netplan/00-installer-config.yaml_

ws1:

![linux](src/images/Part_2/linux2.0-3.png)

ws2:

![linux](src/images/Part_2/linux2.0-4.png)

**Run the netplan apply command to restart the network service**

ws1:

![linux](src/images/Part_2/linux2.0-5.png)

ws2:

![linux](src/images/Part_2/linux2.0-6.png)

### 2.1. Adding a static route manually ###

**Add a static route from one machine to another and back using a `$ ip r add` command.**

**Ping the connection between the machines**

ws1:

`sudo ip r add 172.24.116.8 dev enp0s8`

`ping 172.24.116.8`

![linux](src/images/Part_2/linux2.1-1.png)

ws2:

`sudo ip r add 192.168.100.10 dev enp0s8`

`ping 192.168.100.10`

![linux](src/images/Part_2/linux2.1-2.png)

### 2.2. Adding a static route with saving ###

**Restart the machines**

**Add static route from one machine to another using _etc/netplan/00-installer-config.yaml_ file**

ws1:

![linux](src/images/Part_2/linux2.2-1.png)

ws2:

![linux](src/images/Part_2/linux2.2-2.png)

**Ping the connection between the machines**

ws1:

![linux](src/images/Part_2/linux2.2-3.png)

ws2:

![linux](src/images/Part_2/linux2.2-4.png)

## Part 3. iperf3 utility ##

**== Task ==**

### 3.1. Connection speed ###

**Convert and write results in the report: 8 Mbps to MB/s, 100 MB/s to Kbps, 1 Gbps to Mbps** 

- 8 Mbps is equal to 1 MB/s.
- 100 MB/s is equal to 800 Kbps.
- 1 Gbps is equal to 1000 Mbps.

### 3.2. iperf3 utility ###

**Measure connection speed between ws1 and ws2**

Let's assign the role of a server to ws1 using the command `iperf3 -s`, and the role of a client to ws2 using the command `iperf3 -c 192.168.100.10`.

![linux](src/images/Part_3/linux3.2-1.png)

![linux](src/images/Part_3/linux3.2-2.png)

>Result - 4.99 Gbits/sec.

## Part 4. Network firewall ##

**== Task ==**

### 4.1. iptables utility ###

**Create a /etc/firewall.sh file simulating the firewall on ws1 and ws2:**

ws1:

        #!/bin/sh
        # Deleting all the rules in the "filter" table (default).
        iptables -F
        iptables –X

        iptables -A INPUT -p tcp --sport 22 -j ACCEPT
        iptables -A INPUT -p tcp --sport 80 -j ACCEPT
        iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP
        iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

ws2:

        #!/bin/sh
        # Deleting all the rules in the "filter" table (default).
        iptables -F
        iptables –X

        iptables -A INPUT -p tcp --sport 22 -j ACCEPT
        iptables -A INPUT -p tcp --sport 80 -j ACCEPT
        iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP
        iptables -I OUTPUT 1 -p icmp --icmp-type echo-reply -j ACCEPT

**The following rules should be added to the file in a row:**
1. On  ws1 apply a strategy where a deny rule is written at the beginning and an allow rule is written at the end (this applies to points 4 and 5)

2. On ws2 apply a strategy where an allow rule is written at the beginning and a deny rule is written at the end (this applies to points 4 and 5)

3. Open access on machines for port 22 (ssh) and port 80 (http)

4. Reject  echo reply (machine must not ping, i.e. there must be a lock on OUTPUT)

5. Allow echo reply (machine must be pinged)

_/etc/firewall.sh_ 

![linux](src/images/Part_4/linux4.1-1.png)

![linux](src/images/Part_4/linux4.1-2.png)

**Run the files on both machines with `chmod +x /etc/firewall.sh` and `/etc/firewall.sh` commands.**

`sudo iptables -L --line-number`

![linux](src/images/Part_4/linux4.1-3.png)

![linux](src/images/Part_4/linux4.1-4.png)

`sudo ping -c 10 192.168.100.10`

![linux](src/images/Part_4/linux4.1-4.png)

## 4.2. nmap utility ##

**Use ping command to find a machine which is not pinged, then use nmap utility to show that the machine host is up**

`sudo ping -c 10 172.24.116.8`

![linux](src/images/Part_4/linux4.2-1.png)

`sudo ping -c 10 192.168.100.10`

![linux](src/images/Part_4/linux4.2-2.png)

_Check: nmap output should say: `Host is up`._

`sudo nmap -sS 192.168.100.10`

![linux](src/images/Part_4/linux4.2-3.png)

`sudo nmap -sS 172.24.116.8`

![linux](src/images/Part_4/linux4.2-4.png)


## Part 5. Static network routing ##

**== Task ==**

Network:

![linux](https://edu.21-school.ru/services/storage/download/public_any/182e845c-6712-4356-814d-7295dc8afe30?path=tenantId/96098f4b-5708-4c42-a62c-6893419169b3/gitlab/content_versions/356275/239744c2-c7c4-4a33-b9e3-f79c9c3e4f3a.png)

**Start five virtual machines (3 workstations (ws11, ws21, ws22) and 2 routers (r1, r2))**

### 5.1. Configuration of machine addresses ###

**Set up the machine configurations in _etc/netplan/00-installer-config.yaml_ according to the network in the picture.**

`sudo vim /etc/netplan/00-installer-config.yaml`

![linux](src/images/linux5.1-1.png)

![linux](src/images/linux5.1-2.png)

![linux](src/images/linux5.1-3.png)

![linux](src/images/linux5.1-4.png)

![linux](src/images/linux5.1-5.png)

**Restart the network service. If there are no errors, check that the machine address is correct with the `ip -4` acommand. Also ping ws22 from ws21. Similarly ping r1 from ws11.**

`sudo netplan apply`

`ip -4 a`

![linux](src/images/Part_5/linux5.1-6.png)

![linux](src/images/Part_5/linux5.1-7.png)

![linux](src/images/Part_5/linux5.1-8.png)

![linux](src/images/Part_5/linux5.1-9.png)

![linux](src/images/Part_5/linux5.1-10.png)

`ping -c 10 10.20.0.20`

![linux](src/images/Part_5/linux5.1-11.png)

`ping -c 10 10.10.0.1`

![linux](src/images/Part_5/linux5.1-12.png)

### 5.2. Enabling IP forwarding. ###

**To enable IP forwarding, run the following command on the routers:**

`sysctl -w net.ipv4.ip_forward=1`.

_With this approach, the forwarding will not work after the system is rebooted._

![linux](src/images/Part_5/linux5.2-1.png)

![linux](src/images/Part_5/linux5.2-2.png)

**Open /etc/sysctl.conf file and add the following line:**

`net.ipv4.ip_forward = 1` _With this approach, IP forwarding is enabled permanently._

![linux](src/images/Part_5/linux5.2-3.png)

![linux](src/images/Part_5/linux5.2-4.png)

### 5.3. Default route configuration ###

**Configure the default route (gateway) for the workstations. To do this, add `default` before the router's IP in the configuration file**

`etc/netplan/00-installer-config.yaml`

![linux](src/images/Part_5/linux5.3-1.png)

![linux](src/images/Part_5/linux5.3-2.png)

![linux](src/images/Part_5/linux5.3-3.png)

**Call `ip r` and show that a route is added to the routing table**

![linux](src/images/Part_5/linux5.3-4.png)

![linux](src/images/Part_5/linux5.3-5.png)

![linux](src/images/Part_5/linux5.3-6.png)

**Ping r2 router from ws11 and show on r2 that the ping is reaching. To do this, use the `tcpdump -tn -i eth1`**
**command.**

![linux](src/images/Part_5/linux5.3-7.png)

![linux](src/images/Part_5/linux5.3-8.png)

### 5.4. Adding static routes ###

**Add static routes to r1 and r2 in configuration file. Here is an example for r1 route to 10.20.0.0/26:**

![linux](src/images/Part_5/linux5.4-1.png)

![linux](src/images/Part_5/linux5.4-2.png)

**Call ip r and show route tables on both routers.**

![linux](src/images/Part_5/linux5.4-3.png)

![linux](src/images/Part_5/linux5.4-4.png)

**Run `ip r list 10.10.0.0/[netmask]` and `ip r list 0.0.0.0/0` commands on ws11.**

![linux](src/images/Part_5/linux5.4-5.png)

Маршрут 0.0.0.0/0 в таблице маршрутизации используется, когда хост не знает, куда отправить пакеты, которые не соответствуют более конкретным маршрутам. Однако, если хост имеет более конкретный маршрут для определенной сети, например, 10.10.0.0/18, он будет использовать этот маршрут вместо маршрута по умолчанию. Это позволяет хосту самостоятельно обрабатывать трафик для конкретных сетей и уменьшает нагрузку на маршрутизаторы.

### 5.5. Making a router list ###

**Run the `tcpdump -tnv -i eth0` dump command on r1**

`sudo tcpdump -tnv -i enp0s8`

![linux](src/images/Part_5/linux5.5-1.png)

**Use traceroute utility to list routers in the path from ws11 to ws21**

![linux](src/images/Part_5/linux5.5-2.png)


Каждый пакет имеет ограниченное количество промежуточных узлов, которые он может проходить на своем пути к целевой точке. Это количество узлов определяется значением TTL (Time to Live) в заголовке пакета. Каждый промежуточный маршрутизатор, через который проходит пакет, уменьшает значение TTL на один. Когда TTL достигает нуля, пакет уничтожается, и отправителю возвращается сообщение Time Exceeded, указывающее, что пакет превысил свое время жизни.

Команда traceroute в Linux использует UDP пакеты для отслеживания маршрута к целевому узлу. Она отправляет пакет с TTL (Time to Live) равным 1 и наблюдает за адресом узла, который отвечает. Затем повторяет процесс с увеличением значения TTL (2, 3 и так далее) до достижения цели (что можно увидеть в выводе tcpdump).

Для каждого TTL-запроса traceroute отправляет три пакета и измеряет время, необходимое для прохождения пакетов. Пакеты отправляются на случайный порт, который, вероятно, не занят другими процессами.

Когда traceroute получает сообщение от целевого узла о недоступности порта, это означает, что трассировка завершена, и traceroute прекращает отправку пакетов.

### 5.6. Using ICMP protocol in routing  ###

**Run on r1 network traffic capture going through eth0 with the _tcpdump -n -i eth0 icmp_ command.**

![linux](src/images/Part_5/linux5.6-1.png)

**Ping a non-existent IP (e.g. 10.30.0.111) from ws11 with the**

`ping -c 1 10.100.1.67`

![linux](src/images/Part_5/linux5.6-2.png)


## Part 6. Dynamic IP configuration using DHCP ##

**== Task ==**

**For r2, configure the DHCP service in the /etc/dhcp/dhcpd.conf file:**

**1. Specify the default router address, DNS-server and internal network address.Here is an example of a file for r2:**

![linux](src/images/Part_6/linux6.0-1.png)

**2. Write nameserver `8.8.8.8` in a _resolv.conf_ file**

![linux](src/images/Part_6/linux6.0-2.png)

**Restart the DHCP service with `systemctl restart isc-dhcp-server`. Reboot the ws21 machine with `reboot` and show with `ip a` that it has got an address. Also ping ws22 from ws21.**

![linux](src/images/Part_6/linux6.0-3.png)

![linux](src/images/Part_6/linux6.0-4.png)

![linux](src/images/Part_6/linux6.0-5.png)

**Specify MAC address at ws11 by adding to _etc/netplan/00-installer-config.yaml_:**

`macaddress: 10:10:10:10:10:BA`, `dhcp4: true`

![linux](src/images/Part_6/linux6.0-6.png)

**Сonfigure r1 the same way as r2, but make the assignment of addresses strictly linked to the MAC-address (ws11). Run the same tests**

r1:

![linux](src/images/Part_6/linux6.0-7.png)

![linux](src/images/Part_6/linux6.0-8.png)

![linux](src/images/Part_6/linux6.0-9.png)

ws11:

![linux](src/images/Part_6/linux6.0-10.png)

![linux](src/images/Part_6/linux6.0-11.png)

**Request ip address update from ws21**

![linux](src/images/Part_6/linux6.0-12.png)

`sudo dhclient -r enp0s8` - to reset old address on the enp0s8 interface

![linux](src/images/Part_6/linux6.0-13.png)

`sudo dhclient` - to get a new ip address

![linux](src/images/Part_6/linux6.0-14.png)


## Part 7. NAT ##

**== Task ==**

**In _/etc/apache2/ports.conf_ file change the line `Listen 80` to `Listen 0.0.0.0:80` on ws22 and r1, i.e. make the Apache2 server public**

![linux](src/images/Part_7/linux7.0-1.png)

![linux](src/images/Part_7/linux7.0-2.png)

**Start the Apache web server with service apache2 start command on ws22 and r1**

![linux](src/images/Part_7/linux7.0-3.png)

![linux](src/images/Part_7/linux7.0-4.png)

**Add the following rules to the firewall, created similarly to the firewall from Part 4, on r2:**

**1. delete rules in the filter table - `iptables -F`**

**2. delete rules in the "NAT" table - `iptables -F -t nat`**

**3. drop all routed packets - `iptables --policy FORWARD DROP`**

![linux](src/images/Part_7/linux7.0-5.png)

**Run the file as in Part 4**

![linux](src/images/Part_7/linux7.0-6.png)

**Check the connection between ws22 and r1 with the _ping_ command**

_When running the file with these rules, ws22 should not ping from r1_

![linux](src/images/Part_7/linux7.0-7.png)

**Add another rule to the file:**

**4. allow routing of all ICMP protocol packets**

![linux](src/images/Part_7/linux7.0-8.png)

**Run the file as in Part 4**

![linux](src/images/Part_7/linux7.0-9.png)

**Check connection between ws22 and r1 with the `ping` command**

_When running the file with these rules, ws22 should ping from r1_

![linux](src/images/Part_7/linux7.0-10.png)

**Add two more rules to the file:**

**5. enable SNAT, which is masquerade all local ip from the local network behind r2 (as defined in Part 5 - network 10.20.0.0)**

_Tip: it is worth thinking about routing internal packets as well as external packets with an established connection_

**6. enable DNAT on port 8080 of r2 machine and add external network access to the Apache web server running on ws22**

*Tip: be aware that when you will try to connect, there will be a new tcp connection for ws22 and port 80

![linux](src/images/Part_7/linux7.0-11.png)

**Run the file as in Part 4**

_Before testing it is recommended to disable the NAT network interface in VirtualBox (its presence can be checked with `ip a` command), if it is enabled_

**Check the TCP connection for SNAT by connecting from ws22 to the Apache server on r1 with the `telnet [address] [port]` command**

![linux](src/images/Part_7/linux7.0-12.png)

**Check the TCP connection for DNAT by connecting from r1 to the Apache server on ws22 with the `telnet` command (address r2 and port 8080)**

![linux](src/images/Part_7/linux7.0-13.png)


## Part 8. Bonus. Introduction to SSH Tunnels ##

**==Task==**

**Run a firewall on r2 with the rules from Part 7**

**Start the Apapche web server on ws22 on localhost only (i.e. in _/etc/apache2/ports.conf_ file change the line `Listen 80` to `Listen localhost:80`)**

![linux](src/images/Part_8/linux8.0-1.png)

**Use _Local TCP forwarding_ from ws21 to ws22 to access the web server on ws22 from ws21**

![linux](src/images/Part_8/linux8.0-2.png)

**Use _Remote TCP forwarding_ from ws11 to ws22 to access the web server on ws22 from ws11**

![linux](src/images/Part_8/linux8.0-3.png)

**To check if the connection worked in both of the previous steps, go to a second terminal (e.g. with the Alt + F2) and run the `telnet 127.0.0.1 [local port]` command.**

![linux](src/images/Part_8/linux8.0-4.png)
