from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import HMAC,SHA256
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
import random
import time

user_input = input('Enter your message: ')
with open("Alice/Alicemessage.txt", "w") as f: 
      f.write(user_input)
message = user_input.encode()

p = 37
g = 3

a = random.randint(1, p-1)
A = pow(g,a,p)
print('Alice g^a mod p is:', A)

def KeyGen():
    
    key = RSA.generate(3072)

    with open("Alice/publickey.pem", "wb") as public:
        public_key = key.public_key().export_key()
        public.write(public_key)

    with open("Alice/privatekey.pem", "wb") as private:
        private_key = key.export_key()
        private.write(private_key)

def hash():
    global h
    h = SHA256.new(message)

    global n
    A_bytes = A.to_bytes((A.bit_length() + 7) // 8, byteorder="big")
    n = SHA256.new(A_bytes)
    
    

def sign():
    
    key = RSA.import_key(open('Alice/privatekey.pem').read())
    signature = pkcs1_15.new(key).sign(h)
    diffiesig = pkcs1_15.new(key).sign(n)
    
    with open("Bob/Alicesignature.txt", "wb") as f:
        f.write(signature)
    with open("Bob/Alice-Diffie-Hellman.txt", "w") as z:
        z.write(str(A))
    with open("Bob/Alice-Diffie-Sig.txt", "wb") as c:
        c.write(diffiesig)
    print('Alice g^a mod p signature is:', diffiesig)
 
    


def verify():
    time.sleep(2)
    key = RSA.import_key(open('Bob/publickey.pem').read())
    with open("Bob/Bobmessage.txt") as f:
        s = f.read().encode()
        newhash = SHA256.new(s)

    with open("Alice/Bobsignature.txt", "rb") as f:
        sig = f.read()
    try:    
        pkcs1_15.new(key).verify(newhash,sig)
        print("1")
    except (ValueError, TypeError):
        print("0")


def receive():
    time.sleep(2)
    key = RSA.import_key(open('Bob/publickey.pem').read())

    time.sleep(3)
    with open('Alice\Bob-Diffie-Hellman.txt') as c:
        s = c.read()
        l = int(s).to_bytes((int(s).bit_length() + 7) // 8, byteorder="big")
        newhash = SHA256.new(l)


    
    with open('Alice/Bob-Diffie-Sig.txt', "rb") as v:
        sig = v.read()
        
    try:    
        pkcs1_15.new(key).verify(newhash,sig)
        print("Alice verified Bobs Signature")
    except (ValueError, TypeError):
        print("Bobs signature is invalid")


    with open("Alice/Bob-Diffie-Hellman.txt") as f:
        B = f.read()
        global secretval
        secretval = pow(int(B),a,p)
        print("Alice secret value is:" ,secretval)
        

def keyderiv():
    global finalhash
    l = secretval.to_bytes((secretval.bit_length() + 7) // 8, byteorder="big")
    i = 1
    k = SHA256.new(l)
    while i <= 100:
        k.update(l)
        finalhash = k.hexdigest()
        i += 1
    else:
        print('The final KDF is:',finalhash)

def seed():
    global initial
    seed_value = str(time.time()).encode()
    h =  SHA256.new()
    h.update(seed_value)
    initial = h.hexdigest()
    

def reseed():
    global initial
    combine = initial + str(get_random_bytes(16))
    initial = SHA256.new(combine.encode()).hexdigest()
    


def generate():
    global initial
    h = SHA256.new()
    h.update(initial.encode())
    output = h.hexdigest()

    h2 = SHA256.new()
    h2.update(initial.encode()+ output.encode())
    initial = h2.hexdigest()

    global hash_as_int
    hash_as_int = int(initial,16)
    print(f"hash as integer: {hash_as_int}")
    
    

def sym_enc():
    global nonce
    global ciphertext
    global tag
    global sessionkey
    sessionkey = SHA256.new(finalhash.encode()).digest()
    
    nonce = str(hash_as_int).encode()

    cipher = AES.new(sessionkey, AES.MODE_GCM, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    print('Alice ciphertext: ', ciphertext)


def hmac():
    global h
    combine = nonce + ciphertext + tag
    print('Inputs to HMAC function: ', combine)
    h = HMAC.new(sessionkey, combine, digestmod=SHA256)
    h.update(ciphertext)
    mac_tag = h.digest()
    print('Output for Authenticated Encryption: ', mac_tag)

    with open("Bob/AliceNonce.txt", "wb") as a: 
        a.write(nonce)
    with open("Bob/AliceCipher.txt", "wb") as b:
        b.write(ciphertext)
    with open("Bob/AliceCiphertag.txt", "wb") as c:
        c.write(tag)
    with open("Bob/AliceHMAC.txt","wb") as d:
        d.write(mac_tag)

def decrypt():
    time.sleep(5)
    with open("Alice/BobNonce.txt", "rb") as a: 
        BobNonce = a.read()
        
    with open("Alice/BobCipher.txt", "rb") as b:
        BobCipher = b.read()
        
    with open("Alice/BobCiphertag.txt", "rb") as c:
        BobCiphertag = c.read()
        
    with open("Alice/BobHMAC.txt","rb") as d:
        BobHMAC = d.read()
        
        

    combine = BobNonce + BobCipher + BobCiphertag
    hmac = HMAC.new(sessionkey, combine, digestmod=SHA256)
    print('Alices HMAC value: ', h.digest())
    print('Bobs HMAC value', BobHMAC)
    hmac.update(BobCipher)
    try:
        hmac.verify(BobHMAC)
        print('MAC passed')
    except ValueError:
        print('Key incorrect or message corrupted')
    
    cipher = AES.new(sessionkey, AES.MODE_GCM, BobNonce)
    plaintext = cipher.decrypt_and_verify(BobCipher,BobCiphertag)
    print('This is Bobs message: ', plaintext)





   


    

KeyGen()
hash()
sign()
choice = input("Please type v if you want to verify the signature: ")
if choice == "v":
    verify()
receive()
keyderiv()
seed()
reseed()
generate()
sym_enc()
hmac()
decrypt()

