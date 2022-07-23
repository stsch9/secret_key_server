#! /usr/bin/env bash

curl -XPOST "http://127.0.0.1:5000/api/key" -d "node_id=1" --data-urlencode "secret_key=4af60r8tGduCe5K0ZiR2+kWEyN+2mrPQgFknwoFbyOM=" --data-urlencode "derivation_salt=ECKDrYvn0iCKNwF8SFp4Fw=="
curl "http://127.0.0.1:5000/api/challenge_response?node_id=1"