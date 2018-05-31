#!../../Custom_Python/build/bin/python2
# Description: This script will test to see if the target site supports tl1v1 
# Author: Zach Fleming
# Date: 18/04/2018


# Import The Relevant Libraries
import requests
from termcolor import colored # needed for colored print
import os
import traceback
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# This Class will test to see if the target site supports tl1v1 
class sts_missing():
	
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
				
		# While loop to iterate through the client list and test is it vulnerable to the beast attack
		while i<len(ip_list):
			try:
				client = ip_list[i]	# i is used to iterate through the list of clients 
				client = client.strip() # strip whitespace
				
				
				initial_response = requests.get(client,verify = False, timeout=10) # connect to target url with timeout of ten seconds and ignore ssl cert warnings
				response = self.http_response(initial_response)
				
				# Cnvert Response String To List
				response = response.split("\r\n")
				
				# Loop through each line in the response
				j = 0
				while j <len(response):
					
					# If hsts header is found
					if "Strict-Transport-Security" in response[j]:
						print colored(response[j] + "... [HSTS Found]", 'green')
						self.success_list.append(client)
						
					# if not found
					else:
						print colored(response[j],'cyan')
						
					j+=1
					
				if client in self.success_list:
					print colored("[ CLIENT --> {} HSTS Enforced ]\n".format(client),'green')
				else:
					print colored("[ CLIENT --> {} HSTS Not Enforced ]\n".format(client),'yellow')
					self.manual_recheck_list.append(client)
				
				i+=1 # increment counter --> go to next client
			except Exception as e:
				print (e) # print error code
				print colored("Error Unable To Establish a Connection --> Adding " + client + " to list for manual inpsection later",'red')
				self.manual_recheck_list.append(client)
				i +=1
				continue
				
				
		# Display output to the user 

		
		print colored("\n" + 70 * '-','blue')
		print colored('		RESULTS','cyan',attrs=['bold'])
		print colored(70 * '-','blue')
	
		if len(self.success_list) !=0:
			print colored("\nClients that have the hsts header",'green')
			for element in self.success_list:
				
				print colored(element,'yellow')

		if len(self.manual_recheck_list) !=0:
			print colored("\nCould not determine if these clients had header or not--> May Need To Be MAnually Verified",'red')

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
	print colored("\nStrict Transport Header Detector", 'cyan',  attrs=['bold'])
	print colored(30 * "-", 'cyan')
	print colored("Author: Zach Fleming", 'yellow')
	print colored("Date: 19/04/18", 'green')
	print colored("\nDescription: Determines if a remote https service contains the Strict Transport Header. If this header is not present, it \nmay allow for attackers to downgrade encryption via ssl stripping attacks. This may allow for connection to be intercepted in plaintext ",'cyan')

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
				sts_missing(target_url) # pass url to class
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
				sts_missing(target_filename) # pass url to class
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
