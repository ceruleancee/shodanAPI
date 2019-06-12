
import shodan
import csv
import sys

# first argument(search, scan, etc)
searchType = str(sys.argv[1])
print ("searchType: " + searchType)

# second argument (e.g. 192.168.1.1/24)
searchValue = str(sys.argv[2])
print("searchValue: " + searchValue)

# third argument output file name
fileName = str(sys.argv[3])
print("fileName: " + fileName)

# Shodan object
SHODAN_API_KEY = "APITKEY"
api = shodan.Shodan(SHODAN_API_KEY)

#FILE MANIPULATION
fileOut = open("%s.csv" %fileName, "w")
fieldnames = ['Date','IP', 'Port', 'Org', 'ISP', 'Hostnames', 'Domains', 'OS']
writer = csv.DictWriter(fileOut, fieldnames=fieldnames)
writer.writeheader()

# SEARCH
try:
    if str.lower(searchType) == str.lower("search"):
        results = api.search(searchValue)
    elif str.lower(searchType.lower()) == str.lower("scan"):
        results = api.scan(searchValue)

    # Show the results
    for result in results['matches']:
        #write results to csv
        writer.writerow({'Date': result['timestamp'], 'IP': result['ip_str'], 'Port': result['port'], 'Org': result['org'],
                         'ISP': result['isp'], 'Hostnames': result['hostnames'], 'Domains': result['domains'], 'OS': result['os']})
except shodan.APIError as e:
        print('Error: {}'.format(e))
