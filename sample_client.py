import requests

import hawk

# sample_client.py should work with either sample_server.py
# or tests/server/server.js

credentials = {
    'id': 'dh37fgj492je',
    'key': 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
    'algorithm': 'sha256',
    'user': 'Steve'
}

url = 'http://127.0.0.1:8002/resource/1?b=1&a=2'
params = {'b': 1, 'a': 2}

client = hawk.Client()

header = client.header(url, 'GET', { 'credentials': credentials, 'ext': 'and welcome!' })

headers = [('Authorization', header['field'])]
r = requests.get(url, data=params, headers=headers)

print str(r.status_code) + ' ' + r.text

response = {
    'headers': r.headers
}

if client.authenticate(response, credentials, header['artifacts'], { 'payload': r.text }):
    print "(valid)"
else:
    print "(invalid)"
