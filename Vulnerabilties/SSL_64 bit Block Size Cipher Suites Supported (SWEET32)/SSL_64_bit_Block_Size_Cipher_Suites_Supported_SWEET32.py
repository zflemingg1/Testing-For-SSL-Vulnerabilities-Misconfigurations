#!../../Custom_Python/build/bin/python2
# Description: This script will test to see if the target site is vulnerable to sweet 32 attacks
# Author: Zach Fleming
# Date: 09/04/2018


# Import The Relevant Libraries
import socket # connecting to hosts
import ssl # ssl protocols
from termcolor import colored # needed for colored print
import os
import traceback

# This Class Will Test A Url To Seeif it supports 64 bit ciphers and is vunerable to sweet 32 attack
class SSL_64_bit_Block_Size_Cipher_Suites_Supported_SWEET32():
	
	# Global Variables --> Used for Logic at runtime
	success_list = [] # all urls that are vulnerable to this attack will be displayed in this list
	manual_recheck_list = [] # all unsuccessful connections/urls that are not vulnerable will be added to this list which at the end of runtime
	
	# Ciphers Gotten From Nessus
	CIPHERS = ("ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:AECDH-DES-CBC3-SHA:ADH-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:RSA-PSK-3DES-EDE-CBC-SHA:PSK-3DES-EDE-CBC-SHA:KRB5-DES-CBC3-SHA:KRB5-DES-CBC3-MD5:ECDHE-PSK-3DES-EDE-CBC-SHA:DHE-PSK-3DES-EDE-CBC-SHA")
	
	
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
		protocol = ssl.PROTOCOL_TLSv1 # define the ssl protocol to be used
				
		# While loop to iterate through the client list and test is it vulnerable to the beast attack
		while i<len(ip_list):
			client = ip_list[i]	# i is used to iterate through the list of clients 
			client = client.strip() # strip whitespace
			host = client.split(":")[1] # remove the scheme from the url i.e. https so you would be left with //whatever.com:443
			host = host[2:] # remove // from the url
			port = client.split(":")[2] # Get port number
			port = int(port) # convert string to port

			
			print colored("\nConnecting to " + client,'green',attrs=['bold'])
				
			
			# Try to connect to the client and check headers for cache control
			try:

				# CREATE SOCKET
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(5) # set timeout to 5 seconds
				
				#WRAP Socket --> Convert to SSL and specify protocol Version
				wrappedSocket = ssl.wrap_socket(sock, ssl_version=protocol, ciphers = self.CIPHERS)
	
				# Connect to client with ip x and port y
				wrappedSocket.connect((host, port))
				
				cipher = wrappedSocket.cipher() # get cipher used to initate connection
				ssl_version =  wrappedSocket.version() # get the ssl version used to initate connection
				
				# Close the Connection
				wrappedSocket.close()

				# Successfully Connected So add to results
				print colored ("Successfully Connected To " + host + ":" + repr(port) + " Using " + ssl_version + " With Cipher " + cipher[0] + " ...[VULNERABLE]" ,'green')
				self.success_list.append(client)
				
				i+=1 # increment counter --> go to next client
			except ssl.SSLError as e:
				#print (e) # print error code
				print colored("Exception checking for SWEET32 raised --> Adding " + client + " to list for manual inpsection later",'red')
				self.manual_recheck_list.append(client)
				i +=1
				continue
			except Exception as e:
				print colored("Exception checking for SWEET32 raised --> Adding " + client + " to list for manual inpsection later",'red')
				self.manual_recheck_list.append(client)
				i +=1
				continue
				
		# Display output to the user an
		print colored("\n" + 70 * '-','blue')
		print colored('		RESULTS','cyan',attrs=['bold'])
		print colored(70 * '-','blue')

		# Display Clients that are not vulnerable
		if len(self.success_list) !=0:
			print colored("\nClients THat Support 64 bit Ciphers --> Indicating Vulnerable To Sweet 32",'green')
			for element in self.success_list:
				print colored(element,'yellow')
			
		# DIsplay Clients That Are Possibly Vulnerable
		if len(self.manual_recheck_list) !=0:
			print colored("\nNo 64 bit Ciphers Detected--> Recommended That These Be Manually Verified",'red')
			for element in self.manual_recheck_list:
				print colored(element,'yellow')
			
	# Function to sanitize the response headers
	def http_response(self,response):
		result =  'HTTP/1.1 {} {}\r\n{}\r\n'.format(response.status_code, response.reason , '\r\n'.join(k + ': ' + v for k, v in response.headers.items()))
		return result

# Main Function
def main():
	
	# Display tool info to the user
	print colored(30 * "-", 'cyan')
	print colored("\nSweet32 Attack Detector", 'cyan',  attrs=['bold'])
	print colored(30 * "-", 'cyan')
	print colored("Author: Zach Fleming", 'yellow')
	print colored("Date: 09/04/18", 'green')
	print colored("\nDescription: The Sweet32 attack allows an attacker to recover small portions of plaintext when the text is encrypted with 64-bit block ciphers ",'cyan')
		
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
				SSL_64_bit_Block_Size_Cipher_Suites_Supported_SWEET32(target_url) # pass url to class
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
				SSL_64_bit_Block_Size_Cipher_Suites_Supported_SWEET32(target_filename) # pass url to class
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
