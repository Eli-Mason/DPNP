# Cryptography Imports - For AES and RSA
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# Scapy Import - For networking
# from scapy import * # (currently unusued)

class DPNPRoot: # Root Class

    PrivateKey = rsa.generate_private_key( # Generate root private key
        public_exponent=65537,
        key_size=2048,
    )

    RootKey = PrivateKey.public_key() # Public root key used for cryptographical confirmation of identity

    def __init__(self):
        pass
    
    def checksign(self, signature, output):
        try:
            self.RootKey.verify(signature, output,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True # Signature is valid if point reached
        except:
            return False # Signature is invalid if exception is raised

Root = DPNPRoot()

class User:
    username = '@default'
    
    def __init__(self, username):
        self.username = username
        self.private_key = rsa.generate_private_key( # Generate root private key
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key
        self.public_key_read = self.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        message = f'{self.username} {self.public_key_read.decode()}'.encode()
        self.identity_sign = Root.PrivateKey.sign(message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())

def formUserCheck(username, key):
    return f'{username} {key.decode()}'.encode()

user_eli = User('@Eli_Mason') # Create a user with username "@Eli_Mason"
user_hello = User('@HelloWorld') # Create a user with username "@HelloWorld"

# Confirm identities using root confirmations
if Root.checksign(user_eli.identity_sign,
               formUserCheck('@Eli_Mason', user_eli.public_key_read)):
    print('yes!') # output will be "yes!" because identity signature, key, and username match
else:
    print('no!')

if Root.checksign(user_eli.identity_sign,
               formUserCheck('@HelloWorld', user_eli.public_key_read)):
    print('yes!')
else:
    print('no!') # output will be "no!" because username is invalid
    
if Root.checksign(user_hello.identity_sign,
               formUserCheck('@HelloWorld', user_hello.public_key_read)):
    print('yes!') # output will be "yes!" because identity signature, key, and username match
else:
    print('no!')

