# Shunya-CTF-Writeup
## Medium Challenge

### Echoes of Encryption
#### Approach
1) A seed value was needed in order to decrypt the given cypher text. <br>
2) The description of the question hinted about the Nvidia SMC vulnerability which was discovered in the year 2022. 2CVE's resulted in the google search of the vulnerability and the seed value was one of the CVE numbers (202242269) <br>
3) PS : I initially tried bruteforcing, but didn't work. Then tried researching about the vulnerability and came up with the CVEs.
#### CODE for reference
```
import string
import random

def decrypt_string(encrypted_hex_string, seed):
    random.seed(seed)
    #print(len(encrypted_hex_string))
    allowed_chars = string.ascii_letters + string.digits
    encrypted_bytes = bytes.fromhex(encrypted_hex_string)
    #print(encrypted_bytes)
    encrypted_string = encrypted_bytes.decode()
    #print(len(encrypted_string))
    key = ''.join(random.choices(allowed_chars, k=len(encrypted_string)))
    #print(key)
    decrypted_string = ''
    for i in range(len(encrypted_string)):
        decrypted_char = chr(ord(encrypted_string[i]) ^ ord(key[i]))
        decrypted_string += decrypted_char
    return decrypted_string

for i in range(1,10000000000):
        d = decrypt_string("5e04610a22042638723c571e1a5436142764061f39176b4414204636251072220a35583a60234d2d28082b",202242269)
        if '0CTF{' in d or 1==1:
                print(d)
                #print(d)
        break
```

### Rivest Salted Adleman
#### Approach
1) This is a classic RSA problem. There'll be p,q and e given. But here, p was given and q was XORed with some value which resulted in salted_q.Generally p*q = n ,but in this case it was p*salted_q which was salted_n and then e value was the standard value (65537). <br>
2) Now q has to be found. The description hinted that q was XORed with anywhere from 1-9 or it was XORed with 123456789. There tried both the combination and found out the working one. It was 123456789. XORing salted_q with that would give the real q. Now we have all the values required to calculate the n, phi and d. 
#### CODE
```
from pwn import *
from Crypto.Util.number import inverse,long_to_bytes
p = "95224848836921243754124073456831190902097637702298493988505946669357481749059"
salted_q = "62480590829144807189161429469255353976579455660965599518063804867866301233320"

c = "332390996033761218977578960091058900061139210257883065481008023465866203213646838419152404854307189904898248026722555965488045307811040694129009535565921"

e = 65537

c = int(c)
p = int(p)
salted_q = int(salted_q)
for i in range(0,1):
        q = salted_q ^ 123456789
        try:
                n = p * q
        except Exception:
                continue
        phi = (p-1) * (q-1)
        d = inverse(e,phi)
        new = pow(c,d,n)
        print(long_to_bytes(new),end="\n\n")
```

### AESthetic
#### Approach
1) Two wav files were give. Uploading them in https://morsecode.world/international/decoder/audio-decoder-adaptive.html this website would extract us the message from the hidden beeps. We would be getting the IV and key which are required to crack the Cyphered text. The key is yougotthekeynjoy. But the actual thing extracted from the WAV file was all CAPS. But the key needed for decryption in all small. The IV extracted is 000102030405060708090A0B0C0D0E0F and the cipher text is 69d5deb91a001151db5d98231574a51779acd1a84b9338a6750697c0af7e4591. Using online decoders like cyber chef would help decode the encrypted text

#### Screenshot
![image](https://github.com/Joshua-David1/Shunya-CTF-Writeup/assets/69303816/5293122a-b0b3-4394-9e64-a3e3a90b3af5)

### Uncover the Tea
#### Approach
1) By google searching "rap stars whose fight started from tweets and now has a massive bump on forehead", fetched me some articles. <br>
2) https://heatworld.com/celebrity/news/cardi-b-nicki-minaj-fight-nyfw-party/ this article was about Cardi B's and Nicki Minaj's fight at the New York Fashion Week (NYFW). Hence the flag was NYFW_2018_Cardi_Minaj.

### The Vanishing of Doctor Kumar
#### Approach
1) An mp4 file was given. <br>
2) Loading it in Sonic visualizer and adding the spectogram from the pane menu would show us the flag.

#### Screenshot
![image](https://github.com/Joshua-David1/Shunya-CTF-Writeup/assets/69303816/e55385f7-fd5b-44ae-8533-8842123d51bf)

### BIBBA Part 3

1) 23.23, 89.04 The coordinates were kinda big, but this was the final flag.

## HARD CHALLENGE

### DRUG INJECTION
#### Approach
1) This website is prone to sql injection in the /login.php endpoint. <br>
2) Captured the /login.php POST request with burp and saved it to a text file. Two endpoints were injectable (username and password). Ran an SQLMAP scan sqlmap -r druginj.txt --dump <br>
3) This dumped all the tables contents. The password for the admin user was the flag.

### Can you break the key
#### NOTE : :) Since this was a hard challenge, though it would be really difficult to crack, but it turned out to be quite simple. (Cracked it after the competition).

#### Approach
1) This was also an AES challenge. The encrypted text along with the encryption function was given. The only thing needed was to write a decryption function and find out the key. <br>
2) The description gave a good clue about the key. Figured about the key is in the description. In AES the key needs to be either 128bit(16bytes), 192 (192/8 bytes) bits or 256bits (256/8 bytes). <br>
3) The description spoke about hexadecimal (base 16) and the key for AES is 16 bytes. Hence tried out 0123456789ABCDEF which are the hex digits/characters.

#### CODE
```
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#key = b''

#cipher = AES.new(key, AES.MODE_ECB)
#message = b""
#padded_message = message.ljust((len(message) + 15) // 16 * 16, b'\0')
#ciphertext = cipher.encrypt(padded_message)

#with open("ciphertext.bin", "wb") as f:
    #f.write(ciphertext)

with open("ciphertext.bin",'rb') as f:
        val = f.read()
        key = b'0123456789ABCDEF'
        cip = AES.new(key,AES.MODE_ECB)
        v = cip.decrypt(val)
        print(v)
```
