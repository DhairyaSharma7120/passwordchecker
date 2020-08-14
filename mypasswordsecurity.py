import requests
import sys
import hashlib

def request_to_api(first5hashchar):
	url = "https://api.pwnedpasswords.com/range/" + first5hashchar
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError (f'Error: {res.status_code} Please Check The Api')

	return res

def get_password_breach_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0 

def pwned_api_check(password):
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = request_to_api(first5_char)
  return get_password_breach_count(response, tail)
 
def main():
  password = input("Enter The Password To Check: ")
  count = pwned_api_check(password)
  if count:
  	print(f'{password} was found {count} times... you should probably change your password!')
  else:
  	print(f'{password} was NOT found. Carry on!')
  


main()