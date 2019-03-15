#Tool to search for creds accidentally posted on github 

import json
import os
import re
import syslog
from datetime import datetime,timedelta
import subprocess
import sys

time_range_hrs=2
string=dict()
lasthr=datetime.utcnow()-timedelta(hours = time_range_hrs)
lasthr=datetime.strftime(datetime.strptime(str(lasthr),'%Y-%m-%d %H:%M:%S.%f'),'%Y-%m-%dT%H:%M:%SZ')

#regex patterns for creds
def regex_match(str):	
	check=[('[a-zA-Z0-9_]{39}','google_key'),
	('[0-9a-z]{40}','git_oauth'),
	('[0-9a-zA-Z/+]{40}','aws_access_key'),
	('AKIA[0-9A-Z]{16}','aws_client_id'),
	('[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}','heroku_api'),
	('[a-zA-Z0-9+-_]{30}','other')]

	for check_for in check:
		res=re.search(check_for[0],str)
		if res and res.group().isdigit() and res.group().find("/") is -1:
			if check_for[1]=="other":
				print check_for[1]+": "+res.group()
			else:
				print check_for[1]+": "+res.group()
				return "key: "+res.group()

#detect private keys
	if (str.find("-----BEGIN") is not -1 and str.find("PRIVATE KEY-----") is not -1):
		return "private key found"	
	else:
		return False

def pattern_check(search_str,key):
	count=0
	keywords=list()
	
	if key=="yml":
		keywords=re.findall(r'[pass|password|key]:( )?([^\s]+)',search_str)
	elif key=="properties":
		keywords=re.findall(r'password=([^\s]+)',search_str)
		keywords.extend(re.findall(r'pwd=([^\s]+)',search_str))
		keywords.extend(re.findall(r'key=([^\s]+)',search_str))
	else:
		keywords=re.findall(r'\"([^\"\s]*)\"',search_str)
		keywords=keywords+re.findall(r'\'([^\'\s]*)\'',search_str)
		keywords=keywords+re.findall(r'\'([^\'\s]*)\'',search_str)

	if not keywords:
		print "no keywords found"
		return False

#detects passwords
	for potential in keywords:
		try:
			potential=list(filter(None,potential))[0]
		except IndexError:
			pass
		if potential=="":
			break
		if not (len(potential)>5 and len(potential)<15):
			break
		if re.search(r'\d',potential):
			count=count+1
		if re.search(r'[A-Z]', potential):
			count=count+1
		if re.search(r'[a-z]', potential):
			count=count+1
		if re.search(r'[^a-z|A-Z|\s|0-9]',potential):
			count=count+1
		if count > 3:
			print count
			return potential
		else:
			return False

#alert on findings
def alert(result,url):
	try:
		url=url.replace("/api/v3/repos","").replace("contents/","blob/master/")
		print "key_found: "+result+" in "+url
	except:
		print e

#search github repos
def search_string(key,str):
	try:
		with open(lasthr) as data_file:    
			res_json = json.load(data_file)
		
		for res in res_json['items']:
			full_name=res['full_name']
			cmd="curl -u "+username+":"+token+" https://api.github.com/api/v3/search/code?q="+str+"+repo:"+full_name
			open("exec.sh","w").write(cmd)
			subprocess.check_output("sh exec.sh > output",shell=True)
			with open("output") as output_file:    
				output = json.load(output_file)
			for r in output['items']:
				path= r['path']
				if  r['repository']['private']==False:
					url=r['repository']['contents_url'].replace("{+path}",path)	
					url=url.replace(' ','+')	
					cmd="curl -H 'Accept: application/vnd.github.v4.raw' -u "+username+":"+token+" "+url
					open("exec.sh","w").write(cmd)
					op=subprocess.check_output("sh exec.sh ",shell=True)
					result1=regex_match(op)
					if result1:
						alert(result1,url)
					result2=pattern_check(op,key)
					if result2:
						alert(result2,url)
	except IOError as e:
		print e


def main():
	string["python"]="language:Python"
	string["yml"]="extension:yml"
	string["json"]="language:Json"
	string["js"]="language:javascript"
	string["pl"]="language:perl"
	string["rb"]="language:ruby"
	string["properties"]="extension:properties"

	cmd="curl -u "+username+":"+token+" https://api.github.com/api/v3/search/repositories?pushed:"+lasthr+"..*"
	open("exec.sh","w").write(cmd)
	subprocess.check_output("sh exec.sh > "+lasthr,shell=True)

	for key,value in string.items():
		search_string(key,value)

if __name__ == "__main__":
	main()
