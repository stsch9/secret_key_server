import requests
import json
from oprf.opaque import CreateCredentialRequest, FinalizeRegistrationRequest


def add_user(user_id: int) -> dict:
    headers = {"accept": "application/json",
               "Content-Type": "application/json;charset=UTF-8"}
    data = {"user_id": user_id}
    try:
        response = requests.post("http://127.0.0.1:5000/api/user", data=json.dumps(data), headers=headers)
    except requests.exceptions.RequestException:
        raise Exception("API not available")
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception('Response Code: ' + str(response.status_code))


class Registration:
    def __init__(self):
        self.__blind = b""

    def create_registration_request(self, user_id: int, password: str) -> dict:
        user_id.to_bytes(4, byteorder='big')
        input = user_id.to_bytes(4, byteorder='big') + password.encode('utf-8')
        request_blinded_message, self.__blind = CreateCredentialRequest(input)
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

    def finalize_registration_request(self, user_id: int, password: str, evaluated_message: bytes,
                                      server_public_key: bytes) -> dict:
        user_id.to_bytes(4, byteorder='big')
        input = user_id.to_bytes(4, byteorder='big') + password.encode('utf-8')
        record, export_key = FinalizeRegistrationRequest(input, self.__blind, evaluated_message, server_public_key)

        headers = {"accept": "application/json",
                   "Content-Type": "application/json;charset=UTF-8"}
        data = {"user_id": user_id,
                "record": record.hex()}
        try:
            response = requests.post("http://127.0.0.1:5000/api/user-registration", data=json.dumps(data), headers=headers)
        except requests.exceptions.RequestException:
            raise Exception("API not available")

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception('Response Code: ' + str(response.json()) + str(response.request.body))
