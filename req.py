import requests
import sys
import re
from bs4 import BeautifulSoup
target = 'http://127.0.0.1/DVWA'
sec_level = 'low'
dvwa_user = 'admin'
dvwa_pass = 'password'
session_id = 'kt4pp783v0lda9kp93m2te303u'

data = {
    "username": dvwa_user,
    "password": dvwa_pass,
    "Login": "Login"
}

cookie = {
    "PHPSESSID": session_id,
    "security": sec_level
}
    
r = requests.get("{0}/vulnerabilities/brute/".format(target), params=data, cookies=cookie, allow_redirects=False)
soup = BeautifulSoup(r.text, "html.parser")
data = soup.findAll('div', class_='vulnerable_code_area')
for d in data:
    print(d.text)
