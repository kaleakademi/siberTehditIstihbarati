import requests
import subprocess
import json
import datetime
apiKey=""
mhnIP='http://'
subprocess.check_output('rm -rf /home/securityonion/Desktop/mhn.txt',shell=True)
subprocess.check_output('rm -rf /home/securityonion/Desktop/snortKuralMhn.txt',shell=True)
url=mhnIP+'/api/top_attackers/?api_key='+apiKey+"&hours_ago=24"
cevap=requests.get(url=url)
sid=1000100
for i in cevap.json()['data']:
	log=str(i['count'])+"|"+str(i['honeypot'])+"|"+str(i['source_ip'])+"|"+str(datetime.datetime.now())+"\n"
	dosya=open("mhn.txt","a")
	dosya.write(log)
	dosya.close()
        snortKural="alert tcp any any -> {} any (msg:'Mhn serverda yer alan bir indicatora istek var|{}';sid:{})\n".format(i['source_ip'],i['source_ip'],sid)
        print snortKural
        sid+=1
        dosya=open("snortKuralMhn.txt","a")
        dosya.write(snortKural)
        dosya.close()
