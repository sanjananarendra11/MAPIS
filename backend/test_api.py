import requests

api_url = "http://127.0.0.1:5001/predict"

test_urls = [
    "https://google.com",
    "http://192.168.1.20/secure-login/verify-account.php",
    "http://paypal-login-secure123.com"
]

for u in test_urls:
    try:
        response = requests.post(api_url, json={"url": u})
        print("URL:", u)
        print("Response:", response.json())
        print("-" * 50)
    except Exception as e:
        print("Error:", e)
