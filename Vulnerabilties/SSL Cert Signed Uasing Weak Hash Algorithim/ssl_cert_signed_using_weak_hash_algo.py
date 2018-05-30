#!../../Custom_Python/build/bin/python2
# Description: This script will test to see if the target site is vulnerable to sweet 32 attacks
# Author: Zach Fleming
# Date: 18/04/2018


# Import The Relevant Libraries
from socket import *
import ssl # ssl protocols
from termcolor import colored # needed for colored print
import cryptography.hazmat.backends.openssl
import OpenSSL
import os
import traceback

# This Class Will Test A Url To See if it'#s certificates expire anytime within the next 6 months
class ssl_cert_signed_using_weak_hash_algo():
	
	# Global Variables --> Used for Logic at runtime
	success_list = [] # all successful connections will be added to this list which at the end of runtime will be written to the result file 
	manual_recheck_list = [] # all unsuccessful connections will be added to this list which at the end of runtime will be written to the result file 
	not_supported_list = [] # list that will contain clients that use non acceptable algo's
	
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
			try:
				client = ip_list[i]	# i is used to iterate through the list of clients 
				client = client.strip() # strip whitespace
				host = client.split(":")[1] # remove the scheme from the url i.e. https so you would be left with //whatever.com:443
				host = host[2:] # remove // from the url
				port = client.split(":")[2] # Get port number
				port = int(port) # convert string to port
				certificate = ssl.get_server_certificate((host, port)) # get certificate from client
				crypto = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
				algorithim = crypto.get_signature_algorithm() # get the signature algorithim
			
				# Try to connect to the client and test if it is vulnerable to beast
				setdefaulttimeout(5) # timeout to close socket
				result = (host + ":" + repr(port) + " --> " + algorithim) # format the layout of result
				
				# If statement to check algo --> if known and acceptable print in green, if known and unacceptable print red, if unknown print in yellow --> adds all unknown to supported list so u will have to manually recheck at the end
				if "sha256WithRSAEncryption" in algorithim:
					print colored (result, 'green')
					self.success_list.append(result)
					
				elif "sha1WithRSAEncryption" in algorithim:
					print colored (result, 'red')
					self.not_supported_list.append(result)
				else:
					print colored (result, 'yellow')
					self.success_list.append(result)
					
				i+=1 # increment counter to move on to the next client
				
			except Exception as e:
				print (e) # print error code
				print colored("Exception checking for Weak Certificate Algorithims raised --> Adding " + client + " to list for manual inpsection later",'red')
				self.manual_recheck_list.append(client)
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
				
		if len(self.not_supported_list) !=0:
			print colored("\nList Of Clients That Use Weak Algorithims --> May Need To Be MAnually Verified",'red')
			for element in self.not_supported_list:
				print colored(element,'red')

# Main Function
def main():
	
	# Display tool info to the user
	print colored(30 * "-", 'cyan')
	print colored("\nSSL Certificate Expiry Detector", 'cyan',  attrs=['bold'])
	print colored(30 * "-", 'cyan')
	print colored("Author: Zach Fleming", 'yellow')
	print colored("Date: 09/04/18", 'green')
	print colored("\nDescription: Determines if a remote service uses an SSL certificate chain that has been signed using a cryptographically weak hashing algorithm.\n These signature algorithms are known to be vulnerable to collision attacks.\nAn attacker can exploit this to generate another certificate with the same digital signature, allowing an attacker to masquerade as the affected service",'cyan')
		
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
				ssl_cert_signed_using_weak_hash_algo(target_url) # pass url to class
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
				ssl_cert_signed_using_weak_hash_algo(target_filename) # pass url to class
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
