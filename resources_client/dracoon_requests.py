import requests
import json
from oprf.opaque import CreateCredentialRequest, FinalizeRegistrationRequest, OPAQUE3DH
from nacl.encoding import Base64Encoder
from resources_client.authentication import HmacAuth
from nacl.utils import random
from nacl.bindings import crypto_kx_keypair


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
    def __init__(self, registration_code):
        self.__blind = b""
        self.registration_code = registration_code

    def create_registration_request(self, user_id: int, password: str) -> dict:
        user_id.to_bytes(4, byteorder='big')
        input = user_id.to_bytes(4, byteorder='big') + password.encode('utf-8')
        request_blinded_message, self.__blind = CreateCredentialRequest(input)
        headers = {"accept": "application/json",
                   "Content-Type": "application/json;charset=UTF-8"}
        data = {"user_id": user_id,
                "request": request_blinded_message.hex(),
                "registration_code": self.registration_code}
        try:
            response = requests.post("http://127.0.0.1:5000/api/user-registration-init", data=json.dumps(data),
                                     headers=headers)
        except requests.exceptions.RequestException:
            raise Exception("API not available")

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception('Response Code: ' + str(response.status_code))

    def finalize_registration_request(self, user_id: int, password: str, evaluated_message: bytes,
                                      server_public_key: bytes) -> tuple[dict, bytes]:
        user_id.to_bytes(4, byteorder='big')
        input = user_id.to_bytes(4, byteorder='big') + password.encode('utf-8')
        record, export_key = FinalizeRegistrationRequest(input, self.__blind, evaluated_message, server_public_key)

        headers = {"accept": "application/json",
                   "Content-Type": "application/json;charset=UTF-8"}
        data = {"user_id": user_id,
                "record": Base64Encoder.encode(record).decode('utf-8'),
                "registration_code": self.registration_code}
        try:
            response = requests.post("http://127.0.0.1:5000/api/user-registration-finish", data=json.dumps(data),
                                     headers=headers)
        except requests.exceptions.RequestException:
            raise Exception("API not available")

        if response.status_code == 200:
            return response.json(), export_key
        else:
            raise Exception('Response Code: ' + str(response.json()) + str(response.request.body))


def client_init(user_id: int, password: str, opache_3dh: OPAQUE3DH) -> dict:
    user_id.to_bytes(4, byteorder='big')
    input_password = user_id.to_bytes(4, byteorder='big') + password.encode('utf-8')
    ke1 = opache_3dh.ClientInit(input_password)

    headers = {"accept": "application/json",
               "Content-Type": "application/json;charset=UTF-8"}
    data = {"user_id": user_id,
            "ke1": ke1.hex()}
    try:
        response = requests.post("http://127.0.0.1:5000/api/user-authentication-init", data=json.dumps(data),
                                 headers=headers)
    except requests.exceptions.RequestException:
        raise Exception("API not available")

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception('Response Code: ' + str(response.json()))


def client_finish(session_id: str, opache_3dh: OPAQUE3DH, ke2: bytes) -> tuple[dict, bytes, bytes]:
    headers = {"accept": "application/json",
               "Content-Type": "application/json;charset=UTF-8"}

    cookies = {"session_id": session_id}

    ke3, session_key, export_key = opache_3dh.ClientFinish(b'', b'', ke2)
    data = {"ke3": ke3.hex()}

    try:
        response = requests.post("http://127.0.0.1:5000/api/user-authentication-finish", data=json.dumps(data),
                                 headers=headers, cookies=cookies)
    except requests.exceptions.RequestException:
        raise Exception("API not available")

    if response.status_code == 200:
        return response.json(), session_key, export_key
    else:
        raise Exception('Response Code: ' + str(response.json()) + str(response.request.headers))


def dataroom_init(session_id: bytes, session_key: bytes, name: str) -> dict:
    headers = {"accept": "application/json",
               "Content-Type": "application/json;charset=UTF-8"}

    cookies = {"session_id": session_id}

    data = {'name': name}

    try:
        response = requests.post("http://127.0.0.1:5000/api/dataroom/init", data=json.dumps(data),
                                 headers=headers, cookies=cookies, auth=HmacAuth(session_key))
    except requests.exceptions.RequestException:
        raise Exception("API not available")

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception('Response Code: ' + str(response.json()))
