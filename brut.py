import string
from itertools import product
from time import time
from numpy import loadtxt

def req(password):
    print(password)
    return False
    

def product_loop(generator):
    for p in generator:
        if req(''.join(p)):
            print('\nPassword:', ''.join(p))
            return ''.join(p)
    return False


def bruteforce(max_nchar=16):
    print('1) Comparing with most common passwords / first names')
    common_pass = loadtxt('pass1m.txt', dtype=str)
    for c in common_pass:
        print(c)
    
    print('2) Digits cartesian product')
    for l in range(1, 9):
        generator = product(string.digits, repeat=int(l))
        print("\t..%d digit" % l)
        p = product_loop(generator)
        if p is not False:
            return p

    print('3) Digits + ASCII lowercase')
    for l in range(1, max_nchar + 1):
        print("\t..%d char" % l)
        generator = product(string.digits + string.ascii_lowercase,
                            repeat=int(l))
        p = product_loop(generator)
        if p is not False:
            return p

    print('4) Digits + ASCII lower / upper + punctuation')
    all_char = string.digits + string.ascii_letters + string.punctuation
    for l in range(1, max_nchar + 1):
        print("\t..%d char" % l)
        generator = product(all_char, repeat=int(l))
        p = product_loop(generator)
        if p is not False:
            return p


# EXAMPLE
start = time()
bruteforce() # Try with '123456' or '751345' or 'test2018'
end = time()
print('Total time: %.2f seconds' % (end - start))
