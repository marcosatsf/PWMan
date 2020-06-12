import base64
import string
import secrets
import pprint
import hashlib
import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
    if key == 'd66b386a9e22f786f60373d7c5d3e8256a1b5b6c4b79ed289e4107d8b65800ca':
        return True
    else: return False

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
        for tool_elem in temp.keys():
            for pw_elem in temp[tool_elem].keys():
                temp[tool_elem][pw_elem] = decrypt(temp[tool_elem][pw_elem], k)
        return temp
    except FileNotFoundError as e:
        return {}

def encrypt(d,k):
    # Data not yet encoded
    print(d)
    return Fernet(k).encrypt(d.encode())

def decrypt(d, k):
    # Data already encoded
    return Fernet(k).decrypt(d)


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
                print('Related to?: ')
                n = input()
                proceed = False
                for key in pw_dict.keys():
                    if key == n:
                        proceed = True
                        break
                if proceed is True:
                    alphabet = string.ascii_letters + string.digits
                    while True:
                        # Contains at least one lowerChar, one upperChar, one digit
                        new_pw = ''.join(secrets.choice(alphabet) for i in range(10))
                        if (any(c.islower() for c in new_pw)
                                and any(c.isupper() for c in new_pw)
                                and any(c.isdigit() for c in new_pw)
                                and any(not c.islower()
                                        and not c.isupper()
                                        and not c.isdigit()
                                        for c in new_pw)):
                            break
                    print(f'Generated pw: {new_pw}')
                    pw_dict[n]['past'] = pw_dict[n]['actual']
                    key = manage_key(try_key)
                    pw_dict[n]['actual'] = encrypt(new_pw,key)
                    print('Item Updated!')
                    print('Press enter to proceed...')
                    input()
                else: print('Item not inserted')
            if op == 3:
                pprint.pprint(pw_dict)
                print('Press enter to proceed...')
                input()
            if op == 4:
                print('Related to?: ')
                n = input()
                proceed = False
                for key in pw_dict.keys():
                    if key == n:
                        proceed = True
                        break
                if proceed is True:
                    del pw_dict[n]
        else:
            print('option not recognized, resetting...\n\n')
        if op == 5:
            push_struct(pw_dict, key)
            print('Saved! Press enter to proceed...')
            input()
            break
else: print('Not validated, exiting application...')