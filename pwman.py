import os
import re
import sys
import base64
import string
import secrets
import pprint
import hashlib
from random import randint

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

load_dotenv()
HASHED_KEY = os.getenv('HASH_K')

def print_initial():
    print(
        """
__________________________________________
    ____              _   _
    /    )            /  /|
---/____/------------/| /-|-----__-----__-
  /        | /| /   / |/  |   /   )  /   )
_/_________|/_|/___/__/___|__(___(__/___/_
by MarcosATSF
        """
    )

def clear_screen_by_os():
    if sys.platform == 'win32':
        os.system('cls')
    else:
        os.system('clear')

def verify_key(try_k):
    # Verify notes...
    key = hashlib.sha256(try_k).hexdigest()
    if key == HASHED_KEY:
        return True
    else:
        return False

def manage_key(key_pw):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt4Sec',
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(key_pw)) # Can only use kdf once

def push_struct(data, k):
    with open('pws.data', 'w') as f:
        f.write(str(data))

def pop_struct(k):
    try:
        with open('pws.data', 'r') as f:
            data = f.read()
        temp = eval(data)
        return temp
    except FileNotFoundError as e:
        return {}

def encrypt(d,k):
    # Data not yet encoded
    return Fernet(k).encrypt(d.encode())

def b_encrypt(d,k):
    # Data already encoded
    return Fernet(k).encrypt(d)

def decrypt(d, k):
    # Data already encoded
    return Fernet(k).decrypt(d)

def generate_new_pw(n):
    while True:
        symbols = {0: '@', 1: '#', 2: '$',  3: '%',  4: '&'}
        password = ''
        while not re.findall(r' +', password):
            alphabet = string.ascii_letters + string.digits + ' '
            password = ''.join(secrets.choice(alphabet) for i in range(n))
        real_pass = ''
        for index, each in enumerate(password):
            if each == ' ':
                real_pass += symbols[randint(0, 4)]
            else:
                real_pass += password[index]
        print("Accept this pass <{}>? [Y/n]".format(real_pass))
        another_one = input()
        if another_one == 'Y' or another_one == '\n':
            return real_pass




clear_screen_by_os()
print_initial()
print('Access key: ')
try_key = input().encode()
if verify_key(try_key):
    print('Key Validated!\n'
          'Welcome Marcos Aurélio :)\n\n')
    key = manage_key(try_key)
    pw_dict = pop_struct(key)
    not_exit = True
    while not_exit:
        clear_screen_by_os()
        print_initial()
        print('1. Register pw\n' \
              '2. Update pw\n' \
              '3. Access pw\n' \
              '4. Remove item\n' \
              '5. Securely save & exit\n' \
              'op: ')
        proceed = True
        op = int(input())
        if op > 0 and op < 5:
            if op == 1:

                print('Related to?: ')
                n = input()
                print('pw: ')
                p = input()

                for key in pw_dict.keys():
                    if key == n:
                        print('Item already inserted!')
                        proceed = False
                        break
                if proceed is True:
                    key = manage_key(try_key)
                    pw_dict[n] = {'actual': encrypt(p, key)}

            if op == 2:

                print(pw_dict.keys())
                print('Related to?: ')
                n = input()
                print('How long?[min: 8 chars]: ')
                qtd = int(input())
                proceed = False
                for key in pw_dict.keys():
                    if key == n:
                        proceed = True
                        break
                if proceed is True and qtd > 7:
                    new_pw = generate_new_pw(qtd)
                    print(f'Generated pw: {new_pw}')
                    pw_dict[n]['past'] = pw_dict[n]['actual']
                    key = manage_key(try_key)
                    pw_dict[n]['actual'] = encrypt(new_pw,key)
                    print('Item Updated!')
                    print('Press enter to proceed...')
                    input()
                    push_struct(pw_dict, key)
                else: print('Item not inserted')

            if op == 3:

                for related in pw_dict.keys():
                    for versions in pw_dict[related].keys():
                        key = manage_key(try_key)
                        pw_dict[related][versions] = decrypt(pw_dict[related][versions], key)
                pprint.pprint(pw_dict)
                for related in pw_dict.keys():
                    for versions in pw_dict[related].keys():
                        key = manage_key(try_key)
                        pw_dict[related][versions] = b_encrypt(pw_dict[related][versions], key)
                print('Press enter to proceed...')
                input()

            if op == 4:

                print(pw_dict.keys())
                print('Related to?: ')
                n = input()
                proceed = False
                for key in pw_dict.keys():
                    if key == n:
                        proceed = True
                        break
                if proceed is True:
                    del pw_dict[n]

        elif op == 5:

            push_struct(pw_dict, key)
            print('Saved! Press enter to proceed...')
            input()
            break

        else:

            print('option not recognized, resetting...\n\n')

else: print('Not validated, exiting application...')
