import hashlib
import base64

f = open('password.lst', 'r')
for line in f:
    print(line)
    palavra = line.rstrip('\n')

    hash_object = hashlib.md5(palavra.encode())
    md5_hash = hash_object.hexdigest()
    print(md5_hash)

    message_bytes = md5_hash.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    print(base64_bytes)

    hashSha = hashlib.sha1(base64_bytes.encode())
    sha1_hash = hashSha.hexdigest()
    print(sha1_hash)

f.close()

