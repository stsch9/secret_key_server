import requests
from oprf.opaque import CreateCredentialRequest


def create_registration_request(user_id: int, password: str) -> dict:
    user_id.to_bytes(4, byteorder='big')
    input = user_id.to_bytes(4, byteorder='big') + password.encode('utf-8')
    request_blinded_message, blind = CreateCredentialRequest(input)
    headers = {"accept": "application/json"}
    params = {"user_id": user_id,
              "request": request_blinded_message.hex()}
    try:
        response = requests.get("http://127.0.0.1:5000/api/user-registration", params=params, headers=headers)
    except requests.exceptions.RequestException:
        raise Exception("API not available")

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception('Response Code: ' + str(response.status_code))
