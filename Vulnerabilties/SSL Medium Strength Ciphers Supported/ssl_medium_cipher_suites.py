#!../../Custom_Python/build/bin/python2
# Description: This script will test to see if the target site is vulnerable to sweet 32 attacks
# Author: Zach Fleming
# Date: 18/04/2018


# Import The Relevant Libraries
import socket # connecting to hosts
import ssl # ssl protocols
from termcolor import colored # needed for colored print
import sys
import os
import traceback

# This Class Will Test A Url To See if it'#s certificates expire anytime within the next 6 months
class ssl_medium_cipher_suites():
	
	# Global Variables --> Used for Logic at runtime
	success_list = [] # all successful connections will be added to this list which at the end of runtime will be written to the result file 
	manual_recheck_list = [] # all unsuccessful connections will be added to this list which at the end of runtime will be written to the result file 
	
	# List of ciphers medium strength
	CIPHERS = ('DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:ADH-DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:DES-CBC-MD5:ADH-RC4-MD5:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5')
	
	# These will be used to catch the ssl errors
	sslv3_handshake_error = 0
	
	# Initialize class
	def __init__(self,filename):
		
		# If The User Selected Option 2
		if ".txt" in filename:
			# Open File Containing The Client Info i.e. ip & port
			with open(filename, 'r') as f:
				ip_list = f.readlines()
				
		# If the User Selected Option 1
		else:
			ip_list = [filename]
			
		i = 0 # used as counter to iterate through the list
				
		# While loop to iterate through the client list and test is it vulnerable to the beast attack
		while i<len(ip_list):
			try:
				client = ip_list[i]	# i is used to iterate through the list of clients 
				client = client.strip() # strip whitespace
				host = client.split(":")[1] # remove the scheme from the url i.e. https so you would be left with //whatever.com:443
				host = host[2:] # remove // from the url
				port = client.split(":")[2] # Get port number
				port = int(port) # convert string to port
				
				
				# CREATE SOCKET
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(5) # set timeout to 5 seconds
				
				# WRAP Socket --> Convert to SSL and specify protocol Version
				import ssl
				wrappedSocket = ssl.wrap_socket(sock, ciphers = self.CIPHERS)
				
				# Connect to client with ip x and port y
				wrappedSocket.connect((host, port))
				cipher = wrappedSocket.cipher() # get cipher used to initate connection
				ssl_version =  wrappedSocket.version() # get the ssl version used to initate connection

				# Close the Connection
				wrappedSocket.close()
				
				# Successfully Connected So add to results
				print colored ("Successfully Connected To " + host + ":" + repr(port) + " Using " + ssl_version + " With Cipher " + cipher[0] + " ...[VULNERABLE]" ,'green')
				self.success_list.append(client)
				
				attempt = 0 
				i+=1 # increment counter --> go to next client
			except Exception as e:
				
				
				# Try To See If Wrong Version Of SSL Protoocl
				if "sslv3 alert handshake failure" in str(e) and self.sslv3_handshake_error == 0 :
					try:
			
						import ssl
						self.sslv3_handshake_error+=1
						
						# CREATE SOCKET
						sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						sock.settimeout(5) # set timeout to 5 seconds
						wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1, ciphers = self.CIPHERS)
						
						# Connect to client with ip x and port y
						wrappedSocket.connect((host, port))
						cipher = wrappedSocket.cipher() # get cipher used to initate connection
						ssl_version =  wrappedSocket.version() # get the ssl version used to initate connection
						# Close the Connection
						wrappedSocket.close()
						
						# Successfully Connected So add to results
						print colored ("Successfully Connected To " + host + ":" + repr(port) + " Using " + ssl_version + " With Cipher " + cipher[0] + " ...[VULNERABLE]" ,'green')
						self.success_list.append(client)
				
						attempt = 0 
						i+=1 # increment counter --> go to next client
						self.sslv3_handshake_error = 0
					
					except Exception as e:
						print ('\nError on line {}'.format(sys.exc_info()[-1].tb_lineno)) # Helps Me Debug The Line 
						print (e) # print error code
						
						# Add Results To List
						print colored("Exception checking for Weak ciphers raised --> Adding " + client + " to list for manual inpsection later",'red')
						self.manual_recheck_list.append(client)
						attempt = 0
						i +=1
						self.sslv3_handshake_error = 0
						continue
				
				else:
					
					
					print ('\nError on line {}'.format(sys.exc_info()[-1].tb_lineno)) # Helps Me Debug The Line 
					print (e) # print error code
					
					# Add Results To List
					print colored("Exception checking for Weak ciphers raised --> Adding " + client + " to list for manual inpsection later",'red')
					self.manual_recheck_list.append(client)
					attempt = 0
					i +=1
					continue
				
		# Display output to the user an
				
		print colored("\n" + 70 * '-','blue')
		print colored('		RESULTS','cyan',attrs=['bold'])
		print colored(70 * '-','blue')

		
		# Add The Successfully connected clients to result file
		if len(self.success_list) !=0:
			print colored("\nClients That Do Not Use Weak Hashing Algorithims ",'green')
			for element in self.success_list:
			# Check if file already exists and if not make one
				print colored(element,'yellow')
			
		if len(self.manual_recheck_list) !=0:
			print colored("\nCould not Establish A Connection With The Client--> Need To Be MAnually Verified",'red')
			for element in self.manual_recheck_list:
				print colored(element,'yellow')

# Main Function
def main():
	
	# Display tool info to the user
	print colored(30 * "-", 'cyan')
	print colored("\nSSL Medium Cipher Suite Detector", 'cyan',  attrs=['bold'])
	print colored(30 * "-", 'cyan')
	print colored("Author: Zach Fleming", 'yellow')
	print colored("Date: 18/04/18", 'green')
	print colored("\nDescription: Determines if a remote service uses SSL Ciphers that offeer medium strength encryption. Standard assumption for medium strength ciphers is any that uses key lengths at least\n56 bits and less than 112 bits, or else that uses the 3DES encryption suite",'cyan')
		
	# While loop to ask user to select which option with basic error sanitization
	while True:
		
		# Display Options To The User
		print colored("\nPlease Select One of The Following Options ",'cyan',attrs=['bold'])
		print colored("  1. Single Url",'yellow')
		print colored("  2. File With List of Urls",'yellow')
	
	
		choice = raw_input("\nOption 1 or Option 2: ")
		
		# If user only wishes to test for one url
		if choice == "1":
			os.system('cls' if os.name == 'nt' else 'clear') # Clear Screen
			print colored("Please Enter URL in the following format http://www.whatever.come:443",'cyan')
			
			# Try statement to handle any unexpected errors
			try:
				target_url = raw_input("URL: ") # get url from the user
				ssl_medium_cipher_suites(target_url) # pass url to class
				break
			# catch errors
			except Exception as e:
				print colored("! Error Something Unexpected Occured " + str(e),'red',attrs=['bold'])
				print traceback.print_exc()
		
		# If User wishes to scan a text file conataining a list of urls
		elif choice == "2":
			os.system('cls' if os.name == 'nt' else 'clear') # Clear Screen
			print colored("\nNote text file must be in the following format url and port on each line i.e.",'yellow',attrs=['bold'])
			print colored("\nhttp://www.whatever.com:80\nhttps://www.whatever.com:443'",'yellow')
			print colored("\nPlease Enter Filename including it's location i.e. '/user/Desktop/target_urls.txt'",'cyan')
			
			# Try statement to handle any unexpected errors
			try:
				target_filename = raw_input("Target File: ") # get url from the user
				ssl_medium_cipher_suites(target_filename) # pass url to class
				break
			# catch errors
			except Exception as e:
				print colored("! Error Something Unexpected Occured " + str(e),'red',attrs=['bold'])
				print traceback.print_exc()
				print colored("! Please Try Again",'red')
				
		else:
			os.system('cls' if os.name == 'nt' else 'clear') # Clear Screen
			print colored("! Invalid Option. Please Select Either Option 1 or Option 2",'red',attrs=['bold'])
			
	
main()
