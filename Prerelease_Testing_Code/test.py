# Cryptography Imports - For AES and RSA
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# Scapy Imports - For networking
from scapy.layers.inet import Packet
from scapy.fields import *
from scapy.layers.l2 import Ether


# START Cryptography Section

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
        self.dpnpinit = message
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

# END Cryptography Section

'''
When two DPNP devices want to initialize a connection, first a handshake must be completed.
This handshake verifies the identity and establishes an encrypted connection between the two devices.
This happens in phases:

First, a DPNP packet is sent by host A to host B to host B's MAC address.
The source DPNP address is either an individualized address given by the DPNP Root server,
or a one-time use address generated for the one stream of communication.
This packet uses the activated "New Communication Request" flag, and contains NO DATA.

Second, host B returns a packet to host A.
This packet contains the public key of host B as the data.

Third, host A uses the public key to encrypt a ".dpnpinit" file.
This contains host A's username, public key, and cooresponding related data.

Fourth, host B returns a packet with its own ".dpnpinit" file,
encrypted with host A's public key.
Once both users have shared initialization files, all the data necessary is shared.
Next, a shared key must be agreed upon so the much faster AES encryption protocol can be used.

Fifth, host A sends a new shared key to be used encrypted with host B's public key, then...

Finally, host B responds with an acknowledgement, and new source port number.

At this point, both hosts can send packets back and forth, using their new shared key,
and cryptographic confirmation of the other's identity.

The next data packet host A sends will be the first,
and this is when it sends with a source port number.
'''

class dpnpinit:
    def __init__(self, username, key):
        self.username = username
        self.key = key

    def showData(self):
        return f'{self.username} {self.key}'.encode()

class DPNP(Packet):
    name = "DPNP Header"
    fields_desc=[ XLongField("Source_Address", 0x0),
                  XLongField("Destination_Address", 0x0),
                  ByteField("Duplicate_ID", 0),
                 XByteField("Flags", 0x0),
                ]

# Flag definitions:
New_Communication_Request = 1 << 0
New_Communication_Acknowledgement = 1 << 1

'''
In this example handshake, host A is "@HelloWorld", host B is "@Eli_Mason"
'''

p1 = Ether() / DPNP( # Sent from A to B
    Source_Address = int(0xDAD0FED00EDBEEF),
    Flags = New_Communication_Request) # Example of the First packet in a handshake
print("--- PACKET 1 ---")
p1.show()

A_address = int(0xDAD0FED00EDBEEF)

p2 = Ether() / DPNP( # Sent from B to A
    Destination_Address = A_address,
    Source_Address = int(0xF0F0F1F1F2F2F3FF),
    Flags = New_Communication_Request + New_Communication_Acknowledgement
    ) / raw(user_eli.public_key_read)  # Example of the Second packet in a handshake
print("--- PACKET 2 ---")
p2.show()

host_b_PEM_key = user_eli.public_key_read
HostBKey = serialization.load_pem_public_key(host_b_PEM_key, default_backend())
B_address = int(0xF0F0F0F0F1F1F2F3)

p3 = Ether() / DPNP( # Sent from A to B
    Source_Address = A_address,
    Destination_Address = B_address,
    Flags = New_Communication_Acknowledgement,
    ) / raw(HostBKey.encrypt(
    user_eli.dpnpinit,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    ))


