import requests
import subprocess
import json
import datetime
username=""
password=""
staxxIP='https://'
subprocess.check_output('rm -rf /home/securityonion/Desktop/anomali.txt',shell=True)
subprocess.check_output('rm -rf /home/securityonion/Desktop/snortKuralAnomali.txt',shell=True)
header={'Content-Type':'application/json'}
veri={"username":username,"password":password}
url=staxxIP+'/api/v1/login'
cevap=requests.post(url=url,headers=header,data=json.dumps(veri),verify=False)
token=cevap.json()['token_id']
veri={"token":str(token),"query":"confidence>50","type":"json","size":10}
url=staxxIP+"/api/v1/intelligence"
cevap=requests.post(url=url,headers=header,data=json.dumps(veri),verify=False)
sid=1000001
for i in cevap.json():
	log=i['indicator']+"|"+str(datetime.datetime.now())+"\n"
	dosya=open("anomali.txt","a")
	dosya.write(log)
	dosya.close()
	snortKural="alert tcp any any -> {} any (msg:'Anomalide yer alan bir indicatora istek var|{}';sid:{})\n".format(i['indicator'],i['indicator'],sid)
	print snortKural
	sid+=1
	dosya=open("snortKuralAnomali.txt","a")
	dosya.write(snortKural)
	dosya.close()

