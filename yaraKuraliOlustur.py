# -*- coding: utf-8 -*-
_author="Anil Baran Yelken"
import hashlib
import argparse
def dosyaOku(dosya):
    with dosya:
        return dosya.read()
desc="Dosyadan MD5 tabanlı yara kuralı oluşturucu"
parser=argparse.ArgumentParser(description=desc)
parser.add_argument("Path",help="Full path giriniz")
args=parser.parse_args()
if args:
    path=getattr(args,'Path')
MD5=hashlib.md5(dosyaOku(open(path, 'rb'))).hexdigest()
yaraRules="""import "hash" 
rule md5TabanliYaraRule {
    meta:
        description = "Zararli Olabilecek MD5"
    condition:
        hash.md5(0, filesize) == "degerMD5"     
}
"""
print MD5
yaraRules=yaraRules.replace('degerMD5',str(MD5))
dosya=open("yaraRule.yar","w")
dosya.write(yaraRules)
dosya.close()
