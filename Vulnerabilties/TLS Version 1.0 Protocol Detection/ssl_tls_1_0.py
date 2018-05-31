#!../../Custom_Python/build/bin/python2
# Description: This script will test to see if the target site supports tl1v1 
# Author: Zach Fleming
# Date: 18/04/2018


# Import The Relevant Libraries
import socket # connecting to hosts
import ssl # ssl protocols
from termcolor import colored # needed for colored print
import os
import traceback

# This Class will test to see if the target site supports tl1v1 
class ssl_tls1():
	
	# Global Variables --> Used for Logic at runtime
	success_list = [] # all successful connections will be added to this list which at the end of runtime will be written to the result file 
	manual_recheck_list = [] # all unsuccessful connections will be added to this list which at the end of runtime will be written to the result file 
	
	
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
				
				
				# CREATE SOCKET
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(5) # set timeout to 5 seconds
				# WRAP Socket --> Convert to SSL and specify protocol Version
				wrappedSocket = ssl.wrap_socket(sock, ssl_version=protocol)
				
				# Connect to client with ip x and port y
				wrappedSocket.connect((host, port))
				cipher = wrappedSocket.cipher() # get cipher used to initate connection
				ssl_version =  wrappedSocket.version() # get the ssl version used to initate connection
				
				# Close the Connection
				wrappedSocket.close()
				
				# Successfully Connected So add to results
				print colored ("Successfully Connected To " + host + ":" + repr(port) + " Using " + ssl_version + " ...[VULNERABLE]" ,'green')
				self.success_list.append(client)
				
				i+=1 # increment counter --> go to next client
			except ssl.SSLError as e:
				#print (e) # print error code
				print colored("Error Unable To Establish a Connection Using TLSV1 --> Adding " + client + " to list for manual inpsection later",'red')
				self.manual_recheck_list.append(client)
				i +=1
				continue
				
			except Exception as e:
				#print (e) # print error code
				print colored("Error Unable To Establish a Connection Using TLSV1 --> Adding " + client + " to list for manual inpsection later",'red')
				self.manual_recheck_list.append(client)
				i +=1
				continue
				
				
		# Display output to the user 

		
		print colored("\n" + 70 * '-','blue')
		print colored('		RESULTS','cyan',attrs=['bold'])
		print colored(70 * '-','blue')
	
		if len(self.success_list) !=0:
			print colored("\nSuccessfully Established A SSLv3 Connection With A CBC Cipher Indicating Client is Vulnerable To BEAST",'green')
			for element in self.success_list:
				
				print colored(element,'yellow')

		if len(self.manual_recheck_list) !=0:
			print colored("\nCould not Establish A TLSv1 Connection With A CBC Cipher--> Need To Be MAnually Verified",'red')

			for element in self.manual_recheck_list:
				print colored(element,'yellow')

# Main Function
def main():
	
	# Display tool info to the user
	print colored(30 * "-", 'cyan')
	print colored("\nTLSv1 Detector", 'cyan',  attrs=['bold'])
	print colored(30 * "-", 'cyan')
	print colored("Author: Zach Fleming", 'yellow')
	print colored("Date: 19/04/18", 'green')
	print colored("\nDescription: Determines if a remote service allows for connection via TLSv1 Protocol. If allowed it may allow for a man in the middle exploit, risking the integrity and authentication of data sent\nbetween a website and a browser. Successful exploitation make allow an attacker to view encrypted data in plaintext",'cyan')

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
				ssl_tls1(target_url) # pass url to class
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
				ssl_tls1(target_filename) # pass url to class
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
