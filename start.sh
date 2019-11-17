#!/bin/bash

echo "Your wifi interface is.."
iw dev

read -p 'Choose interface: ' interface

read -p 'Do you want to change the name?(Y/N) ' change


sudo ifconfig $interface down

if [ "$change" == "Y" ] || [ "$change" == "y" ]; then
	read -p 'Enter new interface name: ' newName
	sudo ip link set $interface name $newName
	interface=$newName
fi

sudo iwconfig $interface mode monitor

sudo ifconfig $interface up

sudo ./airodump $interface




