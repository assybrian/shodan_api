#!/usr/bin/env python
#this file is work on python2
#look up https://github.com/achillean/shodan-python
#version 2.0

import shodan
import sys
import os






def host_recon(input_search):
	#protect to connect shodan and get data
	try:
		
		result = api.host(input_search)
		
		
		print("ip\t:\t%s"%result["ip_str"])			#ip
		
		print("hostname:")					#hostname
		if "hostnames" in result:
			for hostname in result["hostnames"]:
				print("\t\t%s"%hostname)



		print("domain:")					#domain
		if "domains" in result:
			for domain in result["domains"]:
				print("\t\t%s"%domain)
				
				
		
		print("open port:\n\t\t"),				#port
		if "ports" in result:
			for port in result["ports"]:
				print("%s "%port),	
			print("")
		
		
		
		print("\n\nfollow is port information:")
		for item in result["data"]:				#port detail
			print("port:\t\t%s"%item["port"])
			
			if "product" in item:
				print("product:\t%s"%item["product"])
			else:
				print("product:\tn/a")
			
			if "server" in item:
				print("server:\t%s"%item["server"])
			else:
				print("server:\t\tn/a")
							
			if "veriosn" in item:
				print("version:\t%s"%item["version"])
			else:
				print("version:\tn/a")
			
			if "vulns" in item:				#port vulns
				print("vulns:")
				count = 0
				for vuln in item["vulns"].iteritems():
					if "cvss" in vuln[1]:
						print("\t%s"%vuln[0]),
						print("cvss:%s\t"%vuln[1]["cvss"]),
						
						count = count+1
						if count ==2:
							count = 0
							print("")
						
			else:
				print("vulns:\t\tn/a")
			print("")
		
		
		
		print("total vulns:\n\t\t")				#total vulns
		count = 0
		if "vulns" in result:
			for vuln in result["vulns"]:
				print("\t%s"%vuln),
				
				count = count+1
				if count ==3:
					count = 0
					print("")
			print("")		
		
		
		
		print("operator system:%s"%result["os"])
		#print("country:\t%s"%result["country_name"])
		#print("city:\t\t%s"%result["city"])
		#print("organization:\t%s"%result["org"])
		#print("isp:\t\t%s"%result["isp"])
		#print("longitude:\t%s"%result["longitude"])
		#print("latitude:\t%s"%result["latitude"])
		print("data last update:%s"%result["last_update"])
		
		

	except shodan.APIError,e:
		print("Error:%s"%e)
	sys.exit(1)





def search_recon(input_search):
	try:
		results=api.search(input_search, limit=5)
		print("Results found:%s"%results['total'])
		if results['total'] == 0 :
			print("their is no result found,maybe check your query again?")
			sys.exit(1)
						
		#print(results)
		
		
		for result in results['matches']:
			print("ip\t:\t%s"%result["ip_str"])			#ip
			
			print("hostname:")					#hostname
			if "hostnames" in result:
				for hostname in result["hostnames"]:
					print("\t\t%s"%hostname)
					
					
					
			print("domain:")					#domain
			if "domains" in result:
				for domain in result["domains"]:
					print("\t\t%s"%domain)		
					
					
					
			if "port" in result:					#port
				print("port:\t\t%s"%result["port"])
			else:
				print("port:\t\tn/a")
			
			
			
			if "product" in result:				#product
				print("product:\t%s"%result["product"])
			else:
				print("product:\tn/a")
			
			
			
			print("operator system:%s"%result["os"])		#os
			
			
			
			if "org" in result:					#org
				print("org:\t\t%s"%result["org"])
			else:
				print("org:\t\tn/a")
				
				
				
			if "isp" in result:					#isp
				print("isp:\t\t%s"%result["isp"])
			else:
				print("isp:\t\tn/a")
		
		
		
			if "location" in result:				#location
				for location_detail in result["location"].iteritems():
					if "country_name" in location_detail[0]:
						country_name=location_detail[1]
					if "city" in location_detail[0]:
						city=location_detail[1]			
					if "longitude" in location_detail[0]:
						longitude=location_detail[1]
					if "latitude" in location_detail[0]:
						latitude=location_detail[1]		
				print("country name:\t%s"%country_name)		
				print("city:\t\t%s"%city)
				print("longitude:\t%s"%longitude)
				print("latitude:\t%s"%latitude)
		
		
		
			if "timestamp" in result:				#last_update
				print("last update:\t%s"%result["timestamp"])
			else:
				print("last update:\tn/a")

			
			
			print("\n\n")


		
	except shodan.APIError,e:
		print("Error:%s"%e)
	sys.exit(1)






if __name__ == "__main__":
	SHODAN_API_KEY = "put your key in here"
	api = shodan.Shodan(SHODAN_API_KEY) 




        #check usage is good or not
	if len(sys.argv) != 3:
		print("To scan host:")
		print("python2 %s -h <input search file>" %sys.argv[0])
		print("=========================================")
		print("To normal search:")
		print("python2 %s -s <input search file>" %sys.argv[0])
        	sys.exit(1)
        

	filepath = sys.argv[2]
	if os.path.isfile(filepath):
  		file = open(filepath, "r")
  		input_search = file.readline().strip('\n')
  		file.close()
	else:
 		print("file does not exist.")
 		sys.exit(1)
		
	
	
	if sys.argv[1] == "-h":
		host_recon(input_search)
	elif sys.argv[1]== "-s":
		search_recon(input_search)
	else:
		print("we only have -h or -s mode.")
		sys.exit(1)
	

