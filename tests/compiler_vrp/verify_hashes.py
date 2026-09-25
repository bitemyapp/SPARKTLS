#!/usr/bin/env python3
import hashlib,sys,json
seed=0x12345678
cases=0
failures=[]
for line in open(sys.argv[1]):
    n,offset,pattern,s256,s512=line.split()
    n,offset,pattern=map(int,(n,offset,pattern))
    if pattern==0: data=bytes(n)
    elif pattern==1: data=bytes([255])*n
    elif pattern==2: data=bytes(i%256 for i in range(n))
    else:
        data=bytearray()
        for i in range(n):
            seed ^= (seed<<13)&0xffffffff
            seed ^= seed>>17
            seed ^= (seed<<5)&0xffffffff
            data.append(seed&255)
    for algorithm,actual in [('sha256',s256),('sha512',s512)]:
        expected=getattr(hashlib,algorithm)(data).hexdigest()
        if expected!=actual:
            failures.append([n,offset,pattern,algorithm,expected,actual])
    cases+=1
print(json.dumps(dict(cases=cases,digests=2*cases,failures=len(failures),examples=failures[:5])))
sys.exit(bool(failures))
