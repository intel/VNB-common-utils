#!/bin/sh

# Fetch all the latest services
echo "=========================Installing dependencies=================================="
apt-get -y update

# Install dependencies for SecMon EMS server
apt-get -y --force-yes install python-pip 
apt-get -y --force-yes install python-dev
apt-get -y --force-yes install libldap2-dev
apt-get -y --force-yes install libsasl2-dev
apt-get -y --force-yes install libssl-dev 

pip install -r requirements_ipsecems.txt
pip install -r requirements_ipsecems_rbac.txt

#copy consul exe to /usr/bin/
echo "========================Copying consul exe to /usr/bin============================"
cp consul /usr/bin/
chmod +x /usr/bin/consul
mkdir /etc/consul_data
mkdir /etc/consul.d

# Copy SecMon code to /etc/ folder
echo "========================Copying IPsec EMS to /etc/=============================="
rm -rf /etc/ipsecems
cp -rf common /etc/ipsecems
rm -rf /etc/ipsecems_rbac
cp -rf ipsecems_rbac /etc/ipsecems_rbac

# create consul_data folder to store consul data
echo "========================Starting Consul Service==============================="
sudo update-rc.d -f /etc/init.d/ipsecems remove
service ipsecems stop
rm /etc/init.d/ipsecems

cp ipsecems /etc/init.d/
chmod +x /etc/init.d/ipsecems

#Update rc run-levels
sudo update-rc.d ipsecems defaults 
service ipsecems start

