#!/bin/bash
#
#
# Situational Awareness
# Kevin Gilstrap
# kevin.gilstrap@sungardas.com
# Sr. Information Security Consultant
# Sungard Availability Services
# April 3, 2016
#
#
#     Function calculates number of bit in a netmask
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
clear
echo "Please run as root"
exit
fi
# Auto-install dependencies
echo "Verifying dependencies are installed..."
apt-get install nbtscan arp-scan nmap -y
clear
# Asks for users input
echo -n "Enter interface name: [ex:  eth0]:  "
read interface
clear
# Asks for users input
echo -n "Would you like to renew the interface? [y/n]:  "
read renew
clear
# Renews interface to get DHCP info
if [ $renew = "y" ]; then
echo "Renewing interface..."
dhclient $interface
clear
fi
#Discovery and parsing
echo "Performing Discovery..."
internal_ip=$(ifconfig $interface | grep 'inet addr:' | tr -d 'addr:' | awk '{print $2}')
clear
echo "Performing Discovery..."
network_addr=$(echo $internal_ip | sed 's/\.[0-9]*$/.0/')
clear
echo "Performing Discovery..."
netmask=$(ifconfig $interface | sed -rn '2s/ .*:(.*)$/\1/p')
clear
echo "Performing Discovery..."
cidr=$(mask2cidr $netmask)
clear
echo "Performing Discovery..."
subnet=$(echo $network_addr/$cidr)
clear
echo "Performing Discovery..."
gw_hostname=$(route | grep 'default' | awk '{print $2}' | tail -n 1)
clear
echo "Performing Discovery..."
gw_ip=$(nslookup $gw_hostname | grep 'Address:' | tail -n 1 | awk '{print $2}')
clear
echo "Performing Discovery..."
externalip=$(curl ipv4.icanhazip.com)
clear
echo "Performing Discovery..."
dnsserver=$(awk '{if(/nameserver/) print $2}' /etc/resolv.conf)
clear
echo "Performing Discovery..."
domain=$(awk '{if(/search/) print $2}' /etc/resolv.conf)
clear
echo "Performing Discovery..."
domaincontrollers=$(nslookup -type=srv _ldap._tcp.dc._msdcs.$domain.com | awk '{print $7}')
clear
echo "Performing Discovery..."
smbtree -N | tee fileshares.tmp
clear
echo "Performing Discovery..."
nmap -sn -PS -n $networks | grep 'Nmap scan' | awk '{print $5}' | tee hosts.tmp
clear
echo "Performing Discovery..."
nbtscan -r $subnet | grep -A 9999 $network_addr | awk '{print $1}' | tr -d 'IP' | tail -n +5 | tee -a hosts.tmp
clear
echo "Performing Discovery..."
arp-scan $subnet | tail -n +3 | grep -B 9999 '^$' | awk '{print $1}' | tee -a hosts.tmp
clear
echo "Performing Discovery..."
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
cat hosts.txt | tee -a networkinfo.txt
echo "$(tput setaf 7)File Shares:  $(tput setaf 3)" | tee -a networkinfo.txt 
cat fileshares.tmp | tee -a networkinfo.txt
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
