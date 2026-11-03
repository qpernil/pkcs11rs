#!/usr/bin/env python3
"""Physical OATH qualification through the exported PKCS #11 ABI.

Creates only UUID-namespaced credentials and removes them in finally. Never
changes the OATH password, resets an application, or touches other applets.
Requires an explicit serial and refuses the preserved YubiKey 10462967.
"""
import argparse
import ctypes as C
import datetime
import hashlib
import hmac
import json
from pathlib import Path
import struct
import uuid

U = C.c_ulong
P = C.c_void_p
class Attribute(C.Structure):
    _fields_ = [("type", U), ("value", P), ("length", U)]
class Mechanism(C.Structure):
    _fields_ = [("type", U), ("parameter", P), ("length", U)]
class OTPParam(C.Structure):
    _fields_ = [("type", U), ("value", P), ("length", U)]
class OTPParams(C.Structure):
    _fields_ = [("params", C.POINTER(OTPParam)), ("count", U)]
class InitArgs(C.Structure):
    _fields_ = [("create", P), ("destroy", P), ("lock", P), ("unlock", P), ("flags", U), ("reserved", P)]

class Module:
    def __init__(self, path, serial):
        self.lib = C.CDLL(str(Path(path).resolve()))
        signatures = {
            "C_Initialize": [P], "C_Finalize": [P],
            "C_GetSlotList": [C.c_ubyte, C.POINTER(U), C.POINTER(U)],
            "C_GetMechanismList": [U,C.POINTER(U),C.POINTER(U)],
            "C_OpenSession": [U,U,P,P,C.POINTER(U)], "C_CloseSession": [U],
            "C_Login": [U,U,P,U], "C_Logout": [U],
            "C_CreateObject": [U,C.POINTER(Attribute),U,C.POINTER(U)],
            "C_DestroyObject": [U,U],
            "C_FindObjectsInit": [U,C.POINTER(Attribute),U],
            "C_FindObjects": [U,C.POINTER(U),U,C.POINTER(U)], "C_FindObjectsFinal": [U],
            "C_GetAttributeValue": [U,U,C.POINTER(Attribute),U],
            "C_SignInit": [U,C.POINTER(Mechanism),U],
            "C_Sign": [U,P,U,P,C.POINTER(U)],
            "C_SignUpdate": [U,P,U], "C_SignFinal": [U,P,C.POINTER(U)],
        }
        for name, args in signatures.items():
            f = getattr(self.lib,name); f.argtypes=args; f.restype=U
        config = C.create_string_buffer(json.dumps({"version":1,"slots":{"serials":[serial]},"ccid":{"applications":["oath"]}}).encode())
        args = InitArgs(None,None,None,None,2,C.cast(config,P))
        self.call("C_Initialize",C.byref(args))
        self.session = U()
        try:
            count=U(); self.call("C_GetSlotList",1,None,C.byref(count))
            slots=(U*count.value)();self.call("C_GetSlotList",1,slots,C.byref(count))
            oath_slots=[]
            for slot in slots[:count.value]:
                size=U();self.call("C_GetMechanismList",slot,None,C.byref(size))
                mechanisms=(U*size.value)();self.call("C_GetMechanismList",slot,mechanisms,C.byref(size))
                if 0x291 in mechanisms[:size.value]:oath_slots.append(slot)
            if len(oath_slots)!=1:raise RuntimeError(f"Expected one OATH slot for selected serial; got {len(oath_slots)}")
            self.call("C_OpenSession",oath_slots[0],6,None,None,C.byref(self.session))
        except BaseException:
            self.call("C_Finalize",None);raise
    def call(self,name,*args,expected=0):
        rv=getattr(self.lib,name)(*args)
        if rv != expected: raise RuntimeError(f"{name}: 0x{rv:x}, expected 0x{expected:x}")
    def find(self,kind=None,hash_=None):
        key_type=U(kind or 0)
        hash_type=U(hash_ or 0)
        queries=[]
        if kind is not None:queries.append(Attribute(0x100,C.cast(C.pointer(key_type),P),C.sizeof(key_type)))
        if hash_ is not None:queries.append(Attribute(0xd0530007,C.cast(C.pointer(hash_type),P),C.sizeof(hash_type)))
        query=(Attribute*len(queries))(*queries)
        self.call("C_FindObjectsInit",self.session,query if queries else None,len(queries))
        try:
            handles=[]
            while True:
                values=(U*32)();count=U();self.call("C_FindObjects",self.session,values,32,C.byref(count))
                handles.extend(values[:count.value])
                if not count.value:return handles
        finally:self.call("C_FindObjectsFinal",self.session)
    def attr(self,key,type_):
        a=Attribute(type_,None,0);self.call("C_GetAttributeValue",self.session,key,C.byref(a),1)
        buf=C.create_string_buffer(a.length);a.value=C.cast(buf,P)
        self.call("C_GetAttributeValue",self.session,key,C.byref(a),1);return buf.raw[:a.length]
    def names(self):
        return {self.attr(key,3):key for key in self.find() if self.attr(key,0)==bytes(U(8))}
    def create(self,name,secret,totp=True,hash_=0x220,period=30,touch=False,key_type=None,counter=0,digits=None):
        if key_type is None:
            key_type=0xd0530002 if totp else (0x23 if hash_==0x220 else 0xd0530003)
        values = [(0,U(8)),(0x100,U(key_type)),(1,C.c_ubyte(1)),(3,C.create_string_buffer(name)),(0x11,C.create_string_buffer(secret)),(0x221,U(digits if digits is not None else (8 if totp else 6))),(0xd0530008,C.c_ubyte(touch))]
        if hash_ is not None:values.append((0xd0530007,U(hash_)))
        if totp:values.append((0x222,U(period)))
        else:values.append((0x22e,C.create_string_buffer(struct.pack(">Q",counter))))
        values.extend([(0x103,C.c_ubyte(1)),(0x162,C.c_ubyte(0))])
        attrs=(Attribute*len(values))(*(Attribute(t,C.cast(C.pointer(v),P),len(name) if t==3 else len(secret) if t==0x11 else 8 if t==0x22e else C.sizeof(v)) for t,v in values))
        key=U();self.call("C_CreateObject",self.session,attrs,len(attrs),C.byref(key));return key.value
    def generate(self,key,totp=True,time=59,retries=True):
        parameters=OTPParams(None,0)
        if totp:
            date=C.create_string_buffer(datetime.datetime.fromtimestamp(time,datetime.timezone.utc).strftime("%Y%m%d%H%M%S").encode())
            item=OTPParam(3,C.cast(date,P),14);parameters=OTPParams(C.pointer(item),1)
        kind=U.from_buffer_copy(self.attr(key,0x100)).value
        mechanism=0xd0530007 if totp else (0x291 if kind==0x23 else 0xd0530008)
        m=Mechanism(mechanism,C.cast(C.pointer(parameters),P),C.sizeof(parameters))
        self.call("C_SignInit",self.session,C.byref(m),key)
        length=U();self.call("C_Sign",self.session,None,0,None,C.byref(length))
        if retries:
            second=U();self.call("C_Sign",self.session,None,0,None,C.byref(second));assert length.value==second.value
            short=C.create_string_buffer(length.value);n=U(length.value-1)
            self.call("C_Sign",self.session,None,0,short,C.byref(n),expected=0x150);assert n.value==length.value
        output=C.create_string_buffer(length.value);self.call("C_Sign",self.session,None,0,output,C.byref(length))
        info=C.cast(output,C.POINTER(OTPParams)).contents;assert info.count==1
        item=info.params[0];assert item.type==0
        return C.string_at(item.value,item.length).decode()
    def close(self):
        try:self.call("C_CloseSession",self.session)
        finally:self.call("C_Finalize",None)

def expected(secret,time,period,hash_,digits):
    value=hmac.new(secret,struct.pack(">Q",time//period),hash_).digest();offset=value[-1]&15
    return str((int.from_bytes(value[offset:offset+4],"big")&0x7fffffff)%10**digits).zfill(digits)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module",required=True);parser.add_argument("--serial",required=True)
    parser.add_argument("--touch",action="store_true",help="Also wait for one physical touch on a dedicated TOTP credential")
    args=parser.parse_args()
    if args.serial in {"10462967","12345678"}:parser.error("Select a dedicated physical test YubiKey; preserved key and virtual gadget are excluded")
    module=Module(args.module,args.serial)
    baseline=module.names();prefix=f"pkcs11rs-test-{uuid.uuid4().hex[:12]}:".encode()
    try:
        # No password is installed or changed by this test. Empty USER login is
        # useful to exercise login/logout on an unprotected test application.
        empty_password=C.create_string_buffer(b"")
        module.call("C_Login",module.session,1,empty_password,0)
        for algorithm,mechanism,secret in [("sha1",0x220,b"12345678901234567890"),("sha256",0x250,b"12345678901234567890123456789012"),("sha512",0x270,b"1234567890"*6+b"1234")]:
            key=module.create(prefix+algorithm.encode(),secret,hash_=mechanism)
            for time in [59,1111111109,1111111111,1234567890,2000000000,20000000000]:
                assert module.generate(key,time=time)==expected(secret,time,30,algorithm,8),algorithm
            # Secret reads are rejected through the public ABI.
            a=Attribute(0x11,None,0);module.call("C_GetAttributeValue",module.session,key,C.byref(a),1,expected=0x11)
        secret=b"12345678901234567890"
        key=module.create(prefix+b"hotp",secret,totp=False)
        assert U.from_buffer_copy(module.attr(key,0x100)).value==0x23
        assert module.attr(key,0x40000600)==bytes(U(0x291))
        wrong=Mechanism(0xd0530008,None,0)
        module.call("C_SignInit",module.session,C.byref(wrong),key,expected=0x68)
        for counter,code in enumerate(["755224","287082","359152","969429","338314","254676","287922","162583","399871","520489"]):
            assert module.generate(key,totp=False)==code,f"HOTP counter {counter}"
        standard_key=key
        aliases=[key for key in module.find(0xd0530003) if module.attr(key,0x102)==prefix+b"hotp"]
        assert len(aliases)==1
        assert module.generate(aliases[0],totp=False)==expected(secret,10,1,"sha1",6)
        assert module.generate(standard_key,totp=False)==expected(secret,11,1,"sha1",6)
        for algorithm,mechanism,key_secret in [("sha1",0x220,secret),("sha256",0x250,b"12345678901234567890123456789012"),("sha512",0x270,b"1234567890"*6+b"1234")]:
            key=module.create(prefix+b"hotp-"+algorithm.encode(),key_secret,totp=False,hash_=mechanism,key_type=0xd0530003)
            assert U.from_buffer_copy(module.attr(key,0x100)).value==0xd0530003
            assert module.attr(key,0x40000600)==bytes(U(0xd0530008))
            wrong=Mechanism(0x291,None,0)
            module.call("C_SignInit",module.session,C.byref(wrong),key,expected=0x68)
            for counter in range(10):
                assert module.generate(key,totp=False)==expected(key_secret,counter,1,algorithm,6),f"HOTP {algorithm} counter {counter}"
            # A nonzero initial counter and eight-digit output exercise the
            # same counter encoding and retry guarantees for all three hashes.
            key=module.create(prefix+b"initial-"+algorithm.encode(),key_secret,totp=False,hash_=mechanism,key_type=0xd0530003,counter=12345,digits=8)
            for counter in range(12345,12348):
                assert module.generate(key,totp=False)==expected(key_secret,counter,1,algorithm,8)
        modern=[key for key in module.find(0xd0530003) if module.attr(key,0x102).startswith(prefix)]
        assert len(modern)==7
        assert {U.from_buffer_copy(module.attr(key,0xd0530007)).value for key in modern}=={0x220,0x250,0x270}
        for hash_,count in [(0x220,3),(0x250,2),(0x270,2)]:
            matches=[key for key in module.find(0xd0530003,hash_) if module.attr(key,0x102).startswith(prefix)]
            assert len(matches)==count
            assert all(U.from_buffer_copy(module.attr(key,0xd0530007)).value==hash_ for key in matches)
        legacy={module.attr(key,0x102) for key in module.find(0x23) if module.attr(key,0x102).startswith(prefix)}
        extended_sha1={module.attr(key,0x102) for key in module.find(0xd0530003,0x220) if module.attr(key,0x102).startswith(prefix)}
        assert legacy==extended_sha1
        for key_type,hash_,error in [(0x23,0x250,0xd1),(0x23,0x270,0xd1),(0xd0530003,0x260,0x13),(0xd0530003,None,0xd0)]:
            try:module.create(prefix+b"invalid-hotp",secret,totp=False,key_type=key_type,hash_=hash_)
            except RuntimeError as failure:assert f"0x{error:x}" in str(failure)
            else:raise AssertionError("HOTP key/hash mismatch was accepted")
        key=module.create(prefix+b"period60",secret,period=60)
        assert module.generate(key,time=1234567890)==expected(secret,1234567890,60,"sha1",8)
        if args.touch:
            key=module.create(prefix+b"touch",secret,touch=True)
            print(f"Touch YubiKey {args.serial} when it blinks for the dedicated OATH test.",flush=True)
            assert module.generate(key,time=59)==expected(secret,59,30,"sha1",8)
            print("PASS: physical touch-required OATH calculation")
        # Force LIST beyond one short-APDU response, without generating codes.
        for index in range(8):
            module.create(prefix+(f"list-{index}-"+"x"*20).encode(),secret)
        assert len(module.names())==len(baseline)+19+int(args.touch)
        # A duplicate name must not overwrite the device credential.
        try:module.create(prefix+b"hotp",b"different",totp=False)
        except RuntimeError as error:assert "0xd1" in str(error)
        else:raise AssertionError("duplicate name overwrote credential")
        module.call("C_DestroyObject",module.session,standard_key)
        assert prefix+b"hotp" not in module.names()
        assert not any(module.attr(key,0x102)==prefix+b"hotp" for key in module.find(0xd0530003))
        print("PASS: 18 RFC 6238 cases, 10 RFC 4226 counters, 39 extended HOTP cases, shared SHA1 counter, hash-filtered discovery, alias deletion, mechanism separation, import validation, buffer retries, secret protection, period 60, response continuation, duplicate protection")
    finally:
        try:
            for name,key in module.names().items():
                if name not in baseline and (name.startswith(prefix) or name.startswith(b"60/"+prefix)):module.call("C_DestroyObject",module.session,key)
            assert module.names()==baseline,"OATH inventory did not return to its baseline"
            print("PASS: dedicated test credentials removed; original OATH inventory preserved")
        finally:module.close()

if __name__=="__main__":main()
