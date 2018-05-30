# Description: This script will test to see if the target site caches https responses"
# Author: Zach Fleming
# Date: 09/04/2018


# Import The Relevant Libraries
import requests
from termcolor import colored # needed for colored print
import os # Needed to clear the screen
import traceback

# This Class Will Test A Url To See if it caches https responses
class Cacheable_HTTPS_response():
	
	# Global Variables --> Used for Logic at runtime
	success_list = [] # all urls that are vulnerable to this attack will be displayed in this list
	manual_recheck_list = [] # all unsuccessful connections/urls that are not vulnerable will be added to this list which at the end of runtime
	
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
			client = ip_list[i]	# i is used to iterate through the list of clients 
			client = client.strip() # strip whitespace
			print colored("\nConnecting to " + client,'green',attrs=['bold'])
				
			
			# Try to connect to the client and check headers for cache control
			try:

				initial_response = requests.get(client,timeout=10)
				response = self.http_response(initial_response)
				
				# Cnvert Response String To List
				response = response.split("\r\n")
				
				# Loop through each line in the response
				j = 0
				cache_control = 0
				pragma_control = 0
				while j <len(response):
					
					# If cache-control / pragmma header is found
					if "cache-control:" in response[j] or "Cache-control:" in response[j]:
						if "no-store" in response[j]:
							print colored(response[j], 'green', attrs=['bold'])
							cache_control = 1
						
					elif "pragma:" in response[j] or "Pragma:" in response[j]:
						if "no-cache" in response[j]:
							print colored(response[j], 'green',attrs=['bold'])
							pragma_control = 1
						
					# if not found
					else:
						print colored(response[j],'cyan')
						
					j+=1
					
				if pragma_control == 1 and cache_control == 1:
					print colored("[ CLIENT --> {} Does Not Cache HTTPS Response Incorrectly ]\n".format(client),'green')
					self.success_list.append(client)
				else:
					print colored("[ CLIENT --> {} Cache Control Not Enforced ]\n".format(client),'yellow')
					self.manual_recheck_list.append(client)
				
				i+=1 # increment counter --> go to next client
			except Exception as e:
				#print (e) # print error code
				print colored("Error Unable To Establish a Connection --> Adding " + client + " to list for manual inpsection later",'red')
				self.manual_recheck_list.append(client)
				i +=1
				continue
				
		# Display output to the user an
		print colored("\n" + 70 * '-','blue')
		print colored('		RESULTS','cyan',attrs=['bold'])
		print colored(70 * '-','blue')

		# Display Clients that are not vulnerable
		if len(self.success_list) !=0:
			print colored("\nCache Contorl Properly Enforced ",'green')
			for element in self.success_list:
				print colored(element,'yellow')
			
		# DIsplay Clients That Are Possibly Vulnerable
		if len(self.manual_recheck_list) !=0:
			print colored("\nNo Cache Detected --> Recommended That These Be Manually Verified",'red')
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
	print colored("\nCacheable HTTPS Response Detector", 'cyan',  attrs=['bold'])
	print colored(30 * "-", 'cyan')
	print colored("Author: Zach Fleming", 'yellow')
	print colored("Date: 09/04/18", 'green')
	print colored("\nDescription: Browsers can store information for purposes of caching and history. Caching is used to improve performance, so that previously displayed information doesn't need to be downloaded again.\nHistory mechanisms are used for user convenience, so the user can see exactly what they saw at the time when the resource was retrieved. If sensitive information is displayed to the user \n(such as their address, credit card details, Social Security Number, or username),\nthen this information could be stored for purposes of caching or history, and therefore retrievable through examining the browser's cache.\nExample May be retrieved by other users who have access to the same computer ",'cyan')
		
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
				Cacheable_HTTPS_response(target_url) # pass url to class
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
				Cacheable_HTTPS_response(target_filename) # pass url to class
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
