from pwn import *
from Crypto.Util.number import *
import gmpy2

conn = remote('2020.redpwnc.tf',31752) #process('server.py') 

message = bytes_to_long(b'redpwnCTF is a cybersecurity competition hosted by the redpwn CTF team.')
e = 65537

data = conn.recvuntil('[3] Exit')

print(data)

p = int(data.splitlines()[0])

near_multiples_of_q = list()
signatures = list()
for i in range(2,5) :
    print('===== ROUND %d ====='%i)
    conn.send('1\n')
    conn.recvuntil('Message:')
    
    conn.send(chr(i)+'\n')

    result = str(conn.recvuntil('[3] Exit'), 'ASCII')
    #print(result)
    lines = result.splitlines()
    sig1, sig2 = [int(x) for x in lines[0].strip().split(' ')]
    derived_a = (inverse(e, p-1) - sig1)%(p-1)
    near_multiples_of_q.append(sig2 + derived_a)
    s = int(lines[1])
    signatures.append((i,s))

q = gmpy2.gcd(near_multiples_of_q[0] - near_multiples_of_q[1], near_multiples_of_q[2] - near_multiples_of_q[1])+1
print('     q = ',q)

n = p*q
print('     n = ',n)
d = inverse(e, (p-1)*(q-1))

secret_signature = pow(message, d, n)
assert pow(secret_signature,e,n) == message
print('===== SENDING SIGNATURE =====')
print('  secret_signature =',secret_signature)
print('  message =',message)

conn.send('2\n')
print(conn.recvuntil('Message:'))
conn.send(long_to_bytes(message))
conn.send('\n')

print(conn.recvuntil('Signature:'))
conn.send('%d\n'%secret_signature)

print(str(conn.recvuntil('[3] Exit'), 'ASCII'))
conn.close()