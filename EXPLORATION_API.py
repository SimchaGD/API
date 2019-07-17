from flask import Flask, request
from flask_restful import Resource, Api
import pandas as pd
from datetime import datetime
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


app = Flask(__name__)
api = Api(app)

# basic api class
class ReadFile(Resource):
    def get(self, username, password):
        # check password
        if not check_password(username, password):
            return "User not recognized."

        # registrate api call in csv file
        registrate_call(username)

        # read in file
        with open("api_test.csv", "r") as f:
            csvFile = f.read()
        return csvFile

# We want to registrate every api call
def registrate_call(usrname):
    # read in all the calls
    df = pd.read_csv("user_calls.csv", sep = ";")

    # define this api call
    df_add = pd.DataFrame({"user": [usrname],
                           "calldate": [datetime.now().ctime()]}, columns= ["user", "calldate"])

    # append the call to the most recent table
    df = pd.concat([df, df_add], sort = False)

    # write to file
    df.to_csv("user_calls.csv", sep= ";", index = False)

def encrypt_password(password):
    password_byte = password.encode() # convert password to bytes

    salt = b'\xadR\xc5\xc2\xe1\xb5\xae\xe5\xa8~\xba\x8e\xca\xff\xc5B'

    # define encryptor
    # use the same encryptor when you want to decrypt
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )

    # derive password and encode
    key = base64.urlsafe_b64encode(kdf.derive(password_byte))
    return key

def decrypt_password(password, key):
    password_byte = password.encode() # convert password to bytes

    salt = b'\xadR\xc5\xc2\xe1\xb5\xae\xe5\xa8~\xba\x8e\xca\xff\xc5B'

    # define encryptor
    # the same encryptor as before
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    # verification will give error if the keys are not the same
    try:
        # decode key and verify
        kdf.verify(password_byte, base64.urlsafe_b64decode(key))
    except: # catch error when keys mismatch
        return False
    return True


def check_password(username, password):
    df = pd.read_csv("user_info.csv", sep = ";")


    if sum(df.user == username) > 0: # check if username is known
        key = df.loc[df.user == username, "key"].item().encode() # find key
    else:
        return False

    return decrypt_password(password, key)

class RegisterUser(Resource):
    def get(self, username, password1, password2):
        # check if password 1 and 2 are the same
        if password1 == password2:
            df = pd.read_csv("user_info.csv", sep = ";")
            if sum(df.user == username) > 0: # username must be unique
                return "Username is not unique"

            # save username and key
            key = encrypt_password(password1)
            key = key.decode()
            df_add = pd.DataFrame({
                                    "user": [username],
                                    "key": [key]
                                   }, columns= ["user", "key"])
            df = pd.concat([df, df_add], sort = False)
            df.to_csv("user_info.csv", sep = ";", index = False)

            return "succesfully registered: {}".format(username)

        else:
            return "Password 1 and password 2 must be the same"

api.add_resource(ReadFile, "/<username>/<password>")
api.add_resource(RegisterUser, "/register/<username>/<password1>/<password2>")

if __name__ == "__main__":
    app.run(debug=True)
