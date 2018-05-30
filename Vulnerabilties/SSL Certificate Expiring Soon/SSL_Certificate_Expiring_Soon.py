#!../../Custom_Python/build/bin/python2
# Description: This script will test to see if the target site is vulnerable to sweet 32 attacks
# Author: Zach Fleming
# Date: 16/04/2018


# Import The Relevant Libraries
from socket import *
import ssl # ssl protocols
from termcolor import colored # needed for colored print
import cryptography.hazmat.backends.openssl
import OpenSSL
import datetime
import time
from dateutil.relativedelta import relativedelta
import os
import traceback

# This Class Will Test A Url To See if it'#s certificates expire anytime within the next 6 months
class SSL_Certificate_Expiring_Soon():
	
	# Global Variables --> Used for Logic at runtime
	has_expired_list = []
	three_month_list = []
	six_month_list = []
	manual_recheck_list = []
	
	# Initialize class
	def __init__(self,filename):
		
		# Display The Colour Codes To User
		print colored("\nColour Codes;", 'cyan',attrs=['bold'])
		print colored("	Certifificate Expired", 'red')
		print colored("	Certifificate Expires Within 3 Months", 'yellow')
		print colored("	Certifificate Expires Within 6 Months\n", 'green')
		
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
				has_expired = crypto.has_expired() # Check if certificate has expired
				DOE = crypto.get_notAfter() # When certificate expires
				
				# Format date and time to get certificate expiry date
				DOE = DOE[:-1]
				old_format = datetime_object = datetime.datetime.strptime(DOE, '%Y%m%d%H%M%S') # EXpiry Of Certificate in American Format
				expires_on = old_format.strftime('%d-%m-%Y %H:%M:%S') # EXpiry Of Certificate in Our time format
				# When Expiry 
				six_months = (datetime.date.today() + datetime.timedelta(6*365/12)).isoformat()
				three_months = (datetime.date.today() + datetime.timedelta(3*365/12)).isoformat()
			
			
				# If it has expired
				if has_expired is True:
					result = (client + " EXPIRED! --> Expired on " + expires_on)
					print colored(result,'red')
					self.has_expired_list.append(result)

				# If expires within six months
				elif expires_on >= three_months and expires_on <= six_months:
					result = (client + " --> Expires on " + expires_on + " ...[6 Months]")
					self.six_month_list.append(result)
					print colored(result,'green')

				# If expires within 3 months
				elif expires_on <= three_months:
					result = (client + " --> Expires on " + expires_on + " ...[3 Months]")
					self.three_month_list.append(result)
					print colored(result,'yellow')

				# Expires after 6 months
				else:
					result = (client + " --> Expires on " + expires_on)
					self.six_month_list.append(result)
					print result
				
					
				i+=1 # increment counter to move on to the next client
			except Exception as e:
				print (e) # print error code
				print colored("Exception checking for Certificate Expiry raised --> Adding " + client + " to list for manual inpsection later",'red')
				self.manual_recheck_list.append(client)
				i +=1
				continue
				
		# Display output to the user an
				
		print colored("\n" + 70 * '-','blue')
		print colored('		RESULTS','cyan',attrs=['bold'])
		print colored(70 * '-','blue')

		
		# Add The Successfully connected clients to result file
		if len(self.has_expired_list) !=0:
			
			print colored("\nClients That Have Already Expired ",'red')
			for element in self.has_expired_list:
			# Check if file already exists and if not make one
				print colored(element,'yellow')
			
		# Add The Successfully connected clients to result file
		if len(self.three_month_list) !=0:
			print colored("\nClients That Expire Within 3 Months ",'yellow')
			for element in self.three_month_list:
			# Check if file already exists and if not make one
				print colored(element,'yellow')
				
		# Add The Successfully connected clients to result file
		if len(self.six_month_list) !=0:
			print colored("\nClients That Expire Within 6 Months ",'green')
			for element in self.six_month_list:
			# Check if file already exists and if not make one
				print colored(element,'green')
				
			
		# Add The Successfully connected clients to result file
		if len(self.manual_recheck_list) !=0:
			print colored("\nClients That Need To Be Manually Rechecked ",'green')
			for element in self.manual_recheck_list:
			# Check if file already exists and if not make one
				print colored(element,'red', attrs=['bold'])

# Main Function
def main():
	
	# Display tool info to the user
	print colored(30 * "-", 'cyan')
	print colored("\nSSL Certificate Expiry Detector", 'cyan',  attrs=['bold'])
	print colored(30 * "-", 'cyan')
	print colored("Author: Zach Fleming", 'yellow')
	print colored("Date: 09/04/18", 'green')
	print colored("\nDescription: Checks to see if the ssl certificate expires anytime in the near future (within 6 months). If the SSL certificate expires and is not renewed, it may result in a dos for users. ",'cyan')
		
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
				SSL_Certificate_Expiring_Soon(target_url) # pass url to class
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
				SSL_Certificate_Expiring_Soon(target_filename) # pass url to class
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
