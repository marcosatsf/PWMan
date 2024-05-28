import os
import random
import re
import sys
import base64
import string
import secrets
import pprint
import hashlib
import time
from collections import Counter
from random import randint
from typing import Dict, Tuple, Callable

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv


load_dotenv()
try:
    MIN_LENGTH = int(os.getenv('MIN_LENGTH'))
except TypeError:
    MIN_LENGTH = 0
SYMBOLS_AVAILABLE = os.getenv('SYMB')
HASHED_KEY = os.getenv('HASH_K')
USERNAME = os.getenv('USERNAME')
COMPILED_FIND_SPACE = re.compile(r' +')

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


def print_key_options_from_map(dict_to_print):
    print(list(dict_to_print.keys()))


def exists_key():
    return True if HASHED_KEY else False


def verify_key(try_k):
    # Verify notes...
    key = hashlib.sha256(try_k).hexdigest()
    if key == HASHED_KEY:
        return True
    else:
        return False


def set_initial_key():
    print('Set your Access key: ')
    access_key = hashlib.sha256(input().encode()).hexdigest()
    print('Set your username: ')
    username = input()
    hash_key_str = 'HASH_K='
    symbols_str = 'SYMB='
    min_length_str = 'MIN_LENGTH='
    username_str = 'USERNAME='
    with open('.env', 'r+') as f:
        envs = f.read()
        if hash_key_str in envs:
            idx = envs.find(hash_key_str) + len(hash_key_str)
            envs = envs[:idx] + access_key + envs[idx:]
            f.seek(0)
            f.write(envs)
        else:
            f.write('\n'+hash_key_str+access_key)
        if not symbols_str in envs:
            f.write('\n' + symbols_str + '@#$%&')
        if not min_length_str in envs:
            f.write('\n' + min_length_str + str(8))
        if not username_str in envs:
            f.write('\n' + username_str + username)
    print('Successfully created user!')
    return access_key, username, '@#$%&', 8


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


def gen_pw_with_len(need_n_chars:int):
    chars = {
        'lower': string.ascii_lowercase,
        'upper': string.ascii_uppercase,
        'num': string.digits,
        'symbol': SYMBOLS_AVAILABLE
    }
    num_types = int(need_n_chars // 4)
    padding_types = int(need_n_chars % 4)
    sorting = random.sample(population=range(need_n_chars), k=need_n_chars)
    password_to_be = [None] * need_n_chars
    for key in chars.keys():
        for _ in range(num_types):
            idx = sorting.pop()
            password_to_be[idx] = secrets.choice(chars[key])
    for _ in range(padding_types):
        idx = sorting.pop()
        password_to_be[idx] = secrets.choice(''.join(chars.values()))
    return ''.join(password_to_be)


def ask_input(n):
    while True:
        curr_password = gen_pw_with_len(n)
        print("Accept this value? <{}> [Y/n]".format(str(curr_password)))
        next_pass = input()
        if next_pass in ('Y', 'y', '\n'):
            return curr_password


def register_new(has_permission:bool=False):
    print_key_options_from_map(pw_dict)
    print('Related to?: ')
    key_name = input()
    if key_name.lower() in [k.lower() for k in pw_dict.keys()]:
        print('Item already inserted not duplicating!')
        time.sleep(2)
        return
    print('pw: ')
    pw = input()
    if has_permission is True:
        key = manage_key(try_key)
        pw_dict[key_name] = {'current': encrypt(pw, key)}


def decide_pw_len():
    print(f'How long?[min: {MIN_LENGTH} chars]: ')
    try:
        return int(input())
    except Exception:
        return MIN_LENGTH
    

def generate_pw_len_n(has_permission:bool=False):
    qtd = decide_pw_len()
    new_pw = ask_input(qtd)
    print(f'Generated pw: {new_pw}')
    print('Press enter to proceed...')
    input()


def update_pw(has_permission:bool=False):
    print_key_options_from_map(pw_dict)
    print('Related to?: ')
    key_name = input()
    if key_name.lower() not in [k.lower() for k in pw_dict.keys()]:
        print('Not able to update key without prior registration!')
        time.sleep(2)
        return
    qtd = decide_pw_len()

    if qtd >= MIN_LENGTH:
        new_pw = ask_input(qtd)
        print(f'Generated pw: {new_pw}')
        pw_dict[key_name]['past'] = pw_dict[key_name]['current']
        key = manage_key(try_key)
        pw_dict[key_name]['current'] = encrypt(new_pw, key)
        print('Item Updated!')
        print('Press enter to proceed...')
        input()
        push_struct(pw_dict, key)
    else:
        print('Item not inserted')

def show_library(has_permission:bool=False):
    for related in pw_dict.keys():
        for versions in pw_dict[related].keys():
            key = manage_key(try_key)
            pw_dict[related][versions] = decrypt(pw_dict[related][versions], key)
        print(f'[{related}]---')
        pprint.pprint(pw_dict[related])
    for related in pw_dict.keys():
        for versions in pw_dict[related].keys():
            key = manage_key(try_key)
            pw_dict[related][versions] = b_encrypt(pw_dict[related][versions], key)
    print('Press enter to proceed...')
    input()


def remove_pw(has_permission:bool=False):
    print(pw_dict.keys())
    print('Related to?: ')
    key_name = input()
    has_permission = False
    for key in pw_dict.keys():
        if key == key_name:
            has_permission = True
            break
    if has_permission is True:
        del pw_dict[key_name]


def save_n_close(has_permission:bool=False):
    push_struct(pw_dict, key)
    print('Saved! Press enter to proceed...')
    input()


OPERATIONS_TABLE: dict[int, tuple[str, Callable[[bool], None]]] = {
            1: ('1. Register pw',register_new),
            2: ('2. Update pw',update_pw),
            3: ('3. Access pw',show_library),
            4: ('4. Generate raw pw',generate_pw_len_n),
            5: ('5. Remove item',remove_pw),
            6: ('6. Securely save & exit',save_n_close),
        }


if __name__ == '__main__':
    clear_screen_by_os()
    print_initial()
    if not exists_key():
        HASHED_KEY, USERNAME, SYMBOLS_AVAILABLE, MIN_LENGTH = set_initial_key()
        time.sleep(2)
        clear_screen_by_os()
        print_initial()
    print('Access key: ')
    try_key = input().encode()
    if verify_key(try_key):
        print('Key Validated!\n'
              f'Welcome {USERNAME} :)\n\n')
        key = manage_key(try_key)
        pw_dict = pop_struct(key)
        not_exit = True
        while not_exit:
            clear_screen_by_os()
            print_initial()
            print(f'Hey {USERNAME}, which option are you looking for?')
            for option_paths in OPERATIONS_TABLE.values():
                print(option_paths[0])
            print('op: ')
            try:
                op = int(input())
            except ValueError:
                continue
            if op in OPERATIONS_TABLE.keys():
                permission = True
                OPERATIONS_TABLE.get(op)[1](permission)
                permission = False
            else:
                print('Option not recognized, resetting...\n\n')

    else:
        print('Not validated, exiting application...')
