import requests
import hashlib
import sys


# Requests API Data
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error Fetching: {res.status_code}, check the API and try again!')
    return res


# Receives the response and compares your password hash with that
def password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# Checks if Password exists in the Response Data
def api_response_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # Converting Your Password into SHA-1
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = api_response_check(password)
        if count:
            print(f'{password} was found {count} time. You should change your Password! :(')
        else:
            print(f'{password} was NOT found. You are all Good :)')
    return 'Script Finished Running.'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
