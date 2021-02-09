#!/bin/bash

iptables -F
iptables -P OUTPUT DROP
iptables -P INPUT DROP

### this policy does not handle IPv6 traffic except to drop it.
#
echo "[+] Desabilitando trafico IPv6..."
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP


###### INPUT chain ######
#
echo "[+] INPUT chain..."

### regras fixas
iptables -A INPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options 
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### insira as portas aqui
iptables -A INPUT -p tcp -s 10.0.2.0/24  --dport 8888 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 1234 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 1111 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 2222 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 3333 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 4444 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 5555 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 6666 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 7777 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 9999 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --dport 48520 -j ACCEPT

###  INPUT LOG 
iptables -A INPUT ! -i lo -j LOG --log-prefix "DROP " --log-ip-options

### Certeza que o loopback fora isso só sai o que eu quero
iptables -I INPUT -i lo -j ACCEPT

###### OUTPUT chain ######
#
echo "[+] OUTPUT chain..."

		
### state tracking rules
iptables -A OUTPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# libera conexão na portas, só copiar regra e substituir o numero
iptables -A FORWARD -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p tcp --dport 21 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 43 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT


###  OUTPUT LOG rule
iptables -A OUTPUT ! -o lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

### Certeza que o loopback e que os tun são permitids sair
iptables  -I OUTPUT -o lo -j ACCEPT
iptables  -I OUTPUT -o tun0 -j ACCEPT
