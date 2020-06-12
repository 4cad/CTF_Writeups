
from pwn import *
import subprocess
import ast
from base64 import b64decode, b64encode
from Crypto.Util.number import long_to_bytes, bytes_to_long

def encode(values) :
    x = 0 
    for v in values :
        x <<= 11
        x += v
    return x

conn = remote('hash-chungdol.ctf.defenit.kr',8960)

for i in range(10) :
    print(conn.recvuntil('Hash :'))
    target = ast.literal_eval(str(conn.recvuntil('[')[:-2].strip(), 'ASCII'))
    print(target)

    x=subprocess.check_output(['Attack.exe', str(target)])
    collisions = ast.literal_eval(str(x.strip(),'ASCII'))

    count = 1
    print('>>>>>>>>>>>>> target = %d <<<<<<<<<<<<<<<<<<<'%target)
    print('>>>>>>>>> FOUND %d COLLISIONS! ' % len(collisions))
    assert len(collisions) >= 5
    for x in collisions[:5] :
        msg = str(b64encode(long_to_bytes(encode(x))), 'ASCII')
        print('SENDING --- '+msg)
        conn.send(msg+'\n')
        print(conn.recvuntil('%d/5'%count))
        count += 1

print(conn.recvuntil('}'))