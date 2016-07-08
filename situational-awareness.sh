#!/bin/bash
#
#
# Situational Awarenessv3
# Kevin Gilstrap
# kevin.gilstrap@sungardas.com
# Sr. Information Security Consultant
# Sungard Availability Services
# April 20, 2016
#
#
# Function calculates number of bit in a netmask
# I did not write this function...
mask2cidr() {
    nbits=0
    IFS=.
    for dec in $1 ; do
        case $dec in
            255) let nbits+=8;;
            254) let nbits+=7;;
            252) let nbits+=6;;
            248) let nbits+=5;;
            240) let nbits+=4;;
            224) let nbits+=3;;
            192) let nbits+=2;;
            128) let nbits+=1;;
            0);;
            *) echo "Error: $dec is not recognised"; exit 1
        esac
    done
    echo "$nbits"
}
# Must be ran with sudo
clear
if [ "$(whoami)" != "root" ]; then
  echo "Please run as root"
exit
fi
# Checks for interface input
if [ -z "$1" ]; then
  echo "[*] Usage:  situational-awareness <interface>"
  exit 0
fi
if [ $1 = "--help" ]; then
  echo "[*] Usage:  situational-awareness <interface>"
  exit 0
fi
if [ $1 = "-h" ]; then
  echo "[*] Usage:  situational-awareness <interface>"
  exit 0
fi

# Auto-install dependencies
echo "Verifying dependencies are installed..."
apt-get install nbtscan arp-scan nmap -y
clear
# Renews interface to get DHCP info
echo Renewing interface... $1
dhclient $1  # comment this out if you do not want to renew the interface
clear

#Discovery and parsing (Brennon Stovall removed the need to use 'head -n 1')
echo "Performing Discovery... INTERNAL IP"
internal_ip=$(ifconfig $1 | grep 'inet\b' | tr -d 'addr:' | awk '{print $2}')
echo 'internal_ip=$(ifconfig $1 | grep 'inet\b' | tr -d 'addr:' | awk '{print $2}')' && echo $internal_ip
gnome-screenshot -w -f internal_ip.png
clear

#Getting the Netmask (Brennon Stovall removed the need to use 'head -n 1')
echo "Performing Discovery...NETMASK"
netmask=$(ifconfig $1 | grep 'inet\b' | tr -d 'Mask:' | awk '{print $4}')
clear
echo "Performing Discovery...CIDR"
cidr=$(mask2cidr $netmask)
clear
#Calculates the Network Address using bitwise AND (Added by Brennon Stovall)
echo "Performing Discovery...NETWORK ADDRESS"
IFS=. read -r i1 i2 i3 i4 <<< "$internal_ip"
IFS=. read -r m1 m2 m3 m4 <<< "$netmask"
network_addr=$(printf "%d.%d.%d.%d\n" "$((i1 & m1))" "$((i2 & m2))" "$((i3 & m3))" "$((i4 & m4))")
clear
echo "Performing Discovery...SUBNET"
subnet=$(echo $network_addr/$cidr)
clear
echo "Performing Discovery...GATEWAY"
gw_ip=$(ip route | grep 'default via' | head -n 1 | awk '{print $3}')
echo 'gw_ip=$(ip route | grep 'default via' | head -n 1 | awk '{print $3}')' && echo $gw_ip
gnome-screenshot -w -f gw.png
clear
echo "Performing Discovery...EXTERNAL IP"
externalip=$(curl -s ipv4.icanhazip.com)
echo 'externalip=$(curl -s ipv4.icanhazip.com)' && echo $external_ip
gnome-screenshot -w -f external_ip.png
clear
echo "Performing Discovery...DNS SERVERS"
dnsserver=$(awk '{if(/nameserver/) print $2}' /etc/resolv.conf)
echo 'dnsserver=$(awk '{if(/nameserver/) print $2}' /etc/resolv.conf)' && echo $dnsserver
gnome-screenshot -w -f dnsservers.png
clear
echo "Performing Discovery...DOMAIN NAME"
domain=$(awk '{if(/search/) print $2}' /etc/resolv.conf)
echo 'domain=$(awk '{if(/search/) print $2}' /etc/resolv.conf)' && echo $domain
gnome-screenshot -w -f domain_name.png
clear
echo "Performing Discovery...DOMAIN CONTROLLERS"
domaincontrollers=$(nslookup -type=srv _ldap._tcp.dc._msdcs.$domain | awk '{print $7}' | cut -d "." -f1)
echo 'domaincontrollers=$(nslookup -type=srv _ldap._tcp.dc._msdcs.$domain | awk '{print $7}' | cut -d "." -f1)' && echo $domaincontrollers
gnome-screenshot -w -f domain_controllers.png
if [[ -z "$domaincontrollers" ]]; then
rm -rf domain_controllers.png
domaincontrollers=$(nslookup -type=srv _ldap._tcp.dc._msdcs.$domain.com | awk '{print $7}' | cut -d "." -f1)
echo 'domaincontrollers=$(nslookup -type=srv _ldap._tcp.dc._msdcs.$domain.com | awk '{print $7}' | cut -d "." -f1)' && echo $domaincontrollers
gnome-screenshot -w -f domain_controllers.png
fi
if [[ -z "$domaincontrollers" ]]; then
rm -rf domain_controllers.png
domaincontrollers=$(nslookup -type=srv _ldap._tcp.dc._msdcs.$domain.local | awk '{print $7}' | cut -d "." -f1)
echo 'domaincontrollers=$(nslookup -type=srv _ldap._tcp.dc._msdcs.$domain.local | awk '{print $7}' | cut -d "." -f1)' && echo $domaincontrollers
gnome-screenshot -w -f domain_controllers.png
fi
clear
echo "Performing Discovery...HOST DISCOVERY - PING SWEEP"
gnome-screenshot -w -d 2 -f ping_sweep.png && nmap -sn -PS -n $networks | grep 'Nmap scan' | awk '{print $5}' | tee hosts.tmp
clear
echo "Performing Discovery...HOST DISCOVERY - NETBIOS SCAN"
gnome-screenshot -w -d 2 -f nbtscan.png && nbtscan -q $subnet | awk '{print $1}' | tee -a hosts.tmp
clear
echo "Performing Discovery...HOST DISCOVERY - ARP SCAN"
gnome-screenshot -w -d 2 -f arp_scan.png && arp-scan -q -I $1 --localnet | awk '{print $1}' | tail -n +3 | head -n -3 | tee -a hosts.tmp
clear
echo "Performing Discovery...PARSING HOST DISCOVERY RESULTS"
sort -u hosts.tmp | sed '/^\s*$/d' | tee hosts.txt
clear
echo "Situational Awareness Complete"
if [[ -z "$gw_ip" ]]; then
gw_ip="Could not determine gateway"
fi
if [[ -z "$externalip" ]]; then
externalip="Could not resolve external address"
fi
if [[ -z "$domaincontrollers" ]]; then
domaincontrollers="No domain controllers were found"
fi
if [[ -z "$dnsserver" ]]; then
dnsserver="No DNS servers were found"
fi
if [[ -z "$internal_ip" ]]; then
internal_ip="No IP Address assigned to interface"
fi
if [[ -z "$domain" ]]; then
domain="Domain name not found"
fi
echo "$(tput setaf 2)--------------------------------------------------------" | tee networkinfo.txt
echo $(tput setaf 7)Domain Name:  $(tput setaf 3)$domain | tee -a networkinfo.txt
echo $(tput setaf 7)IP Address:  $(tput setaf 3)$internal_ip | tee -a networkinfo.txt
echo $(tput setaf 7)Default Gateway:  $(tput setaf 3)$gw_ip | tee -a networkinfo.txt
echo $(tput setaf 7)Network Address:  $(tput setaf 3)$network_addr | tee -a networkinfo.txt
echo $(tput setaf 7)Network Mask:  $(tput setaf 3)$netmask | tee -a networkinfo.txt
echo $(tput setaf 7)Network CIDR:  $(tput setaf 3)$subnet | tee -a networkinfo.txt
echo $(tput setaf 7)DNS Servers:  $(tput setaf 3)$dnsserver | tee -a networkinfo.txt
echo $(tput setaf 7)External IP Address:  $(tput setaf 3)$externalip | tee -a networkinfo.txt
echo $(tput setaf 7)Domain Controllers:  $(tput setaf 3)$domaincontrollers | tee -a networkinfo.txt
echo "$(tput setaf 7)Hosts: $(tput setaf 3)" | tee -a networkinfo.txt
sort -n -t. +0 -1 +1 -2 +2 -3 +3 -4 hosts.txt | uniq -u | tee -a networkinfo.txt
echo "$(tput setaf 7)"
echo "$(tput setaf 7)Scan has been appeneded to situationalawareness.log"
echo "$(tput setaf 2)--------------------------------------------------------$(tput setaf 7)" | tee -a networkinfo.txt
# Appends output to log file
cat networkinfo.txt >> situationalawareness.log
# Clean-up of files
rm -rf hosts.tmp
rm -rf hosts.txt
rm -rf fileshares.tmp
rm -rf networkinfo.txt
exit
