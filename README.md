# PWMan
A password manager written in Python language which helps you create, read, update and delete (CRUD) \
passwords from a file.

## Firsts Steps
Set a key to access the manager and be used as key to en/decryption on `.env` file. \
Remember to hash (SHA256) this key first, before copy+paste to env. variable.

## Running manager
Just execute like a python program: \
`python pwman.py` \
After it's necessary to input the same key that you hashed before, but now, in 
raw string. Doing that, you're now able to access the manager console, and 
add, modify, remove and check your stored passwords. \
*All passwords are stored encrypted on `pws.data` file
