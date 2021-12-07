#!/bin/bash
#Dropping Source Routed Packets
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
#Enable TCP SYN Cookies (SYN flooding protection)
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
#Drop ICMP redirect messages
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
#Dont Send ICMP redirect messages
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
#Enable source address spoofing protection
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
#Enable logging of packets with forged source addresses
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
#There are changes in kernel >= 4.7 which need some additional changes for this to work:
echo 1 > /proc/sys/net/netfilter/nf_conntrack_helper 
modprobe ip_conntrack_ftp
iptables -F
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
iptables -A FORWARD -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A FORWARD -d 255.255.255.255 -j DROP

# iptables -F
# iptables -P OUTPUT ACCEPT
# iptables -P INPUT ACCEPT

#echo "[+] Desabilitando trafico IPv6..."
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP

###### INPUT chain ######
echo "[+] INPUT chain..."

### regras fixas
### Certeza que o loopback fora isso só sai o que eu quero
iptables -A INPUT -i lo -j ACCEPT
iptables -A  INPUT -i docker0 -j ACCEPT
#Allow previously initiated connections to bypass rules
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#Mess up nmap scan timing, and start dropping packets
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 7 -j DROP
#Defeat nmap port scanning in non standard configurations (XMAS , Banner Scan, etc)
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP
### insira as portas aqui 
# ssh em caso de necessidade
#iptables -A  INPUT -p tcp -m tcp --dport 8888 -j ACCEPT  
iptables -A INPUT -p tcp -i eth1 --dport 8888 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 21 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 445 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 1111 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 1194 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 1234 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 2222 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 3001 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 3333 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 4444 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 5555 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 6666 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 7777 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 9999 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 3000 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 5000 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 8089 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 8080 -j ACCEPT

###### OUTPUT chain ######

echo "[+] OUTPUT chain..."
iptables  -A OUTPUT -o lo -j ACCEPT
iptables  -A OUTPUT -o tun0 -j ACCEPT
iptables  -A OUTPUT -o tun1 -j ACCEPT
iptables  -A OUTPUT -o docker0 -j ACCEPT

### state tracking rules
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

 #libera conexão na portas, só copiar regra e substituir o numero
iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -A  OUTPUT -p udp -m udp --dport 1194	-m conntrack --ctstate NEW -j ACCEPT
iptables -A  OUTPUT -p udp -m udp --dport 1337	-m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
