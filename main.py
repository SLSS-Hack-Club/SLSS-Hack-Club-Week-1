import hashlib
from urllib.request import urlopen
 
def readwordlist(url):
    try:
        wordlistfile = urlopen(url).read()
    except Exception as e:
        print("Hey there was some error while reading the wordlist, error:", e)
        exit()
    return wordlistfile
 
def hash(wordlistpassword):
    result = hashlib.sha1(wordlistpassword.encode())
    return result.hexdigest()
 
 
def bruteforce(guesspasswordlist, password_hash):
    for guess_password in guesspasswordlist:
        if hash(guess_password) == actual_password_hash:
            print("Hey! your password is:", guess_password,
                  "\nIt was really easy to guess it, please change your password. (:")
            exit()
 
# wordlist 
url = 'https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt'

#input password to look through wordlist
actual_password = input("Please enter your password to check: ")
actual_password_hash = hash(actual_password)
wordlist = readwordlist(url).decode('UTF-8')
guesspasswordlist = wordlist.split('\n')
 
# Running the Brute Force attack
bruteforce(guesspasswordlist, actual_password_hash)
 
# If the password is not in wordlist, the following code will be executed
print("Hey! I couldn't guess this password, it was not in my wordlist, this is good news! You have a good password, you win! (: ")