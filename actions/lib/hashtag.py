#!/usr/bin/python
"""
Name:           HashTag: Parse and Identify Password Hashes
Version:        0.41
Date:           11/05/2013
Author:         Smeege
Contact:        SmeegeSec@gmail.com

Description:    HashTag.py is a python script written to parse and identify password hashes.  It has three main arguments
                which consist of identifying a single hash type (-sh), parsing and identifying multiple hashes from a
                file (-f), and traversing subdirectories to locate files which contain hashes  and parse/identify them (-d).
                Many common hash types are supported by the CPU and GPU cracking tool Hashcat.  Using an additional
                argument (-hc) hashcat modes will be included in the output file(s).

Copyright (c) 2013, Smeege Sec (http://www.smeegesec.com)
All rights reserved.
Please see the attached LICENSE file for additional licensing information.
"""
import string

hashDict = dict()

hashcatDict = { \
'MD5': '0', 'md5($pass.$salt)': '10', 'Joomla': '11', 'md5($salt.$pass)': '20', 'osCommerce, xt:Commerce': '21', 'm\
d5(unicode($pass).$salt)': '30', 'md5($salt.unicode($pass))': '40', 'HMAC-MD5 (key = $pass)': '50', 'HMAC-MD5 (key\
= $salt)': '60', 'SHA1': '100', 'nsldap, SHA-1(Base64), Netscape LDAP SHA': '101', 'sha1($pass.$salt)': '110', 'nsl\
daps, SSHA-1(Base64), Netscape LDAP SSHA': '111', 'Oracle 11g': '112', 'Oracle 11g, SHA-1(Oracle)': '112', 'sha1($s\
alt.$pass)': '120', 'sha1(strtolower($username).$pass),  SMF >= v1.1': '121', 'OSX v10.4, v10.5, v10.6': '122', 's\
ha1(unicode($pass).$salt)': '130', 'MSSQL(2000)': '131', 'MSSQL(2005)': '132', 'sha1($salt.unicode($pass))': '140',\
 'EPiServer 6.x < v4': '141', 'HMAC-SHA1 (key = $pass)': '150', 'HMAC-SHA1 (key = $salt)': '160', 'sha1(LinkedIn)':\
 '190', 'MySQL': '200', 'MySQL4.1/MySQL5': '300', 'phpass, MD5(Wordpress), MD5(phpBB3)': '400', 'md5crypt, MD5(Unix\
), FreeBSD MD5, Cisco-IOS MD5': '500', 'SHA-1(Django)': '800', 'MD4': '900', 'md4($pass.$salt)': '910', 'NTLM': '10\
00', 'Domain Cached Credentials, mscash': '1100', 'SHA256': '1400', 'sha256($pass.$salt)': '1410', 'sha256($salt.$p\
ass)': '1420', 'sha256(unicode($pass).$salt)': '1430', 'sha256($salt.unicode($pass))': '1440', 'EPiServer 6.x > v4'\
: '1441', 'HMAC-SHA256 (key = $pass)': '1450', 'HMAC-SHA256 (key = $salt)': '1460', 'descrypt, DES(Unix), Tradition\
al DES': '1500', 'md5apr1, MD5(APR), Apache MD5': '1600', 'SHA512': '1700', 'sha512($pass.$salt)': '1710', 'SSHA-51\
2(Base64), LDAP {SSHA512}': '1711', 'sha512($salt.$pass)': '1720', 'OSX v10.7': '1722', 'sha512(unicode($pass).$sal\
t)': '1730', 'MSSQL(2012)': '1731', 'sha512($salt.unicode($pass))': '1740', 'HMAC-SHA512 (key = $pass)': '1750', 'H\
MAC-SHA512 (key = $salt)': '1760', 'sha512crypt, SHA512(Unix)': '1800', 'Domain Cached Credentials2, mscash2': '210\
0', 'Cisco-PIX MD5': '2400', 'WPA/WPA2': '2500', 'Double MD5': '2600', 'md5(md5($pass))': '2600', 'vBulletin < v3.8\
.5': '2611', 'vBulletin > v3.8.5': '2711', 'IPB2+, MyBB1.2+': '2811', 'LM': '3000', 'Oracle 7-10g, DES(Oracle)': '3\
100', 'bcrypt, Blowfish(OpenBSD)': '3200', 'MD5(Sun)': '3300', 'md5(md5(md5($pass)))': '3500', 'md5(md5($salt).$pas\
s)': '3610', 'md5($salt.md5($pass))': '3710', 'md5($pass.md5($salt))': '3720', 'WebEdition CMS': '3721', 'md5($salt\
.$pass.$salt)': '3810', 'md5(md5($pass).md5($salt))': '3910', 'md5($salt.md5($salt.$pass))': '4010', 'md5($salt.md5\
($pass.$salt))': '4110', 'md5($username.0.$pass)': '4210', 'md5(strtoupper(md5($pass)))': '4300', 'md5(sha1($pass))\
': '4400', 'sha1(sha1($pass))': '4500', 'sha1(sha1(sha1($pass)))': '4600', 'sha1(md5($pass))': '4700', 'MD5(Chap)':\
 '4800', 'SHA-3(Keccak)': '5000', 'Half MD5': '5100', 'Password Safe SHA-256': '5200', 'IKE-PSK MD5': '5300', 'IKE-\
PSK SHA1': '5400', 'NetNTLMv1-VANILLA / NetNTLMv1+ESS': '5500', 'NetNTLMv2': '5600', 'Cisco-IOS SHA256': '5700', 'S\
amsung Android Password/PIN': '5800', 'RipeMD160': '6000', 'Whirlpool': '6100', 'TrueCrypt 5.0+ PBKDF2-HMAC-RipeMD1\
60': '621Y', 'TrueCrypt 5.0+ PBKDF2-HMAC-SHA512': '622Y', 'TrueCrypt 5.0+ PBKDF2-HMAC-Whirlpool': '623Y', 'TrueCryp\
t 5.0+ PBKDF2-HMAC-RipeMD160 boot-mode': '624Y', 'TrueCrypt 5.0+': '62XY', 'AIX {smd5}': '6300', 'AIX {ssha256}': '\
6400', 'AIX {ssha512}': '6500', '1Password': '6600', 'AIX {ssha1}': '6700', 'Lastpass': '6800', 'GOST R 34.11-94':\
'6900', 'Fortigate (FortiOS)': '7000', 'OSX v10.8': '7100', 'GRUB 2': '7200', 'IPMI2 RAKP HMAC-SHA1': '7300', 'sha2\
56crypt, SHA256(Unix)': '7400'}


# Check whether a string consists of only hexadecimal characters.
def isHex(singleString):
    for c in singleString:
        if not c in string.hexdigits: return False
    return True


# Check whether a string consists of hexadecimal characters or '.' or '/'
def isAlphaDotSlash(singleString):
    for c in singleString:
        if not c in string.ascii_letters and not c in string.digits and not c in '.' and not c in '/': return False
    return True


# Identifies a single hash string based on attributes such as character length, character type (hex, alphanum, etc.), and specific substring identifiers.
# These conditional statements are ordered specifically to address efficiency when dealing with large inputs
def identifyHash(singleHash):
    if len(singleHash) == 32 and isHex(singleHash):
        hashDict[singleHash] = ['MD5', 'NTLM', 'MD4', 'LM', 'RAdmin v2.x', 'Haval-128', 'MD2', 'RipeMD-128', 'Tiger-128', 'Snefru-128', 'MD5(HMAC)', 'MD4(HMAC)', 'Haval-128(HMAC)', 'RipeMD-128(HMAC)', 'Tiger-128(HMAC)', \
        'Snefru-128(HMAC)', 'MD2(HMAC)', 'MD5(ZipMonster)', 'MD5(HMAC(Wordpress))', 'Skein-256(128)', 'Skein-512(128)', 'md5($pass.$salt)', 'md5($pass.$salt.$pass)', 'md5($pass.md5($pass))', 'md5($salt.$pass)', 'md5($salt.$pass.$salt)', \
        'md5($salt.$pass.$username)', 'md5($salt.\'-\'.md5($pass))', 'md5($salt.md5($pass))', 'md5($salt.md5($pass).$salt)', 'md5($salt.MD5($pass).$username)', 'md5($salt.md5($pass.$salt))', 'md5($salt.md5($salt.$pass))', 'md5($salt.md5(md5($pass).$salt))', \
        'md5($username.0.$pass)', 'md5($username.LF.$pass)', 'md5($username.md5($pass).$salt)', 'md5(1.$pass.$salt)', 'md5(3 x strtoupper(md5($pass)))', 'md5(md5($pass)), Double MD5', 'md5(md5($pass).$pass)', 'md5(md5($pass).$salt), vBulletin < v3.8.5', 'md4($salt.$pass)', 'md4($pass.$salt)' \
        'md5(md5($pass).md5($pass))', 'md5(md5($pass).md5($salt))', 'md5(md5($salt).$pass)', 'md5(md5($salt).md5($pass))', 'md5(md5($username.$pass).$salt)', 'md5(md5(base64_encode($pass)))', 'md5(md5(md5($pass)))', 'md5(md5(md5(md5($pass))))', \
        'md5(md5(md5(md5(md5($pass)))))', 'md5(sha1($pass))', 'md5(sha1(base64_encode($pass)))', 'md5(sha1(md5($pass)))', 'md5(sha1(md5($pass)).sha1($pass))', 'md5(sha1(md5(sha1($pass))))', 'md5(strrev($pass))', 'md5(strrev(md5($pass)))', \
        'md5(strtoupper(md5($pass)))', 'md5(strtoupper(md5(strtoupper(md5(strtoupper(md5($pass)))))))', 'strrev(md5($pass))', 'strrev(md5(strrev(md5($pass))))', '6 x md5($pass)', '7 x md5($pass)', '8 x md5($pass)', '9 x md5($pass)', '10 x md5($pass)', '11 x md5($pass)', '12 x md5($pass)']
    elif len(singleHash) > 32 and singleHash[32] == ':' and singleHash.count(':') == 1:
        hashDict[singleHash] = ['md5($salt.$pass.$salt)', 'md5($salt.md5($pass))', 'md5($salt.md5($pass.$salt))', 'md5($salt.md5($salt.$pass))', 'md5($username.0.$pass)', 'md5(md5($pass).md5($salt))', 'md5(md5($salt).$pass)', 'HMAC-MD5 (key = $pass)', 'HMAC-MD5 (key = $salt)', 'md5($pass.md5($salt))', \
        'WebEdition CMS', 'IPB2+, MyBB1.2+', 'md5(unicode($pass).$salt)', 'Domain Cached Credentials2, mscash2', 'md5($salt.unicode($pass))', 'vBulletin > v3.8.5', 'DCC2', 'md5(md5($pass).$salt), vBulletin < v3.8.5']
    elif len(singleHash) == 40:
        hashDict[singleHash] = ['SHA1', 'Tiger-160', 'Haval-160', 'RipeMD160', 'HAS-160', 'SHA-1(HMAC)', 'Tiger-160(HMAC)', 'Haval-160(HMAC)', 'RipeMD-160(HMAC)', 'Skein-256(160)', 'Skein-512(160)', 'sha1(LinkedIn)', 'SAPG', 'SHA-1(MaNGOS)', 'SHA-1(MaNGOS2)', \
        'sha1($salt.$pass.$salt)', 'sha1(md5($pass.$salt))', 'sha1(md5($pass).$userdate.$salt)', 'sha1($pass.$username.$salt)', 'sha1(md5($pass).$pass)', 'sha1(md5(sha1($pass)))', 'xsha1(strtolower($pass))', 'sha1($pass.$salt)', 'sha1($salt.$pass)', \
        'sha1($salt.$username.$pass.$salt)', 'sha1($salt.md5($pass))', 'sha1($salt.md5($pass).$salt)', 'sha1($salt.sha1($pass))', 'sha1($salt.sha1($salt.sha1($pass)))', 'sha1($username.$pass)', 'sha1($username.$pass.$salt)', 'sha1(md5($pass))', \
        'sha1(md5($pass).$salt)', 'sha1(md5(sha1(md5($pass))))', 'sha1(sha1($pass))', 'sha1(sha1($pass).$salt)', 'sha1(sha1($pass).substr($pass,0,3))', 'sha1(sha1($salt.$pass))', 'sha1(sha1(sha1($pass)))', 'sha1(strtolower($username).$pass)']
    elif len(singleHash) > 40 and singleHash[40] == ':' and singleHash.count(':') == 1:
        hashDict[singleHash] = ['sha1($pass.$salt)', 'HMAC-SHA1 (key = $pass)', 'HMAC-SHA1 (key = $salt)', 'sha1(unicode($pass).$salt)', 'sha1($salt.$pass)', 'sha1($salt.unicode($pass))', 'Samsung Android Password/PIN', 'sha1($salt.$pass.$salt)', 'sha1(md5($pass.$salt))', 'sha1(md5($pass).$userdate.$salt)', 'sha1($pass.$username.$salt)']
    elif len(singleHash) == 64 and isHex(singleHash):
        hashDict[singleHash] = ['Keccak-256', 'sha256(md5($pass).$pass))', 'Skein-256', 'Skein-512(256)', 'Ventrilo', 'WPA-PSK PMK', 'GOST R 34.11-94', 'Haval-256', 'RipeMD-256', 'SHA256', 'sha256(md5($pass))', 'sha256(sha1($pass))', 'Snefru-256', 'HMAC-SHA256 (key = $salt)', 'SHA-3(Keccak)']
    elif len(singleHash) > 64 and singleHash[64] == ':' and singleHash.count(':') == 1:
        hashDict[singleHash] = ['sha256(md5($pass.$salt))', 'sha256(md5($salt.$pass))', 'SHA-256(RuneScape)', 'sha256(sha256($pass).$salt)', 'Haval-256(HMAC)', 'RipeMD-256(HMAC)', 'sha256($pass.$salt)', 'sha256($salt.$pass)', 'SHA-256(HMAC)', 'Snefru-256(HMAC)', 'HMAC-SHA256 (key = $pass)', 'sha256(unicode($pass).$salt)', 'sha256($salt.unicode($pass))']
    elif singleHash.startswith('sha1$'):
        hashDict[singleHash] = ['SHA-1(Django)']
    elif singleHash.startswith('$H$'):
        hashDict[singleHash] = ['phpass, MD5(Wordpress), MD5(phpBB3)']
    elif singleHash.startswith('$P$'):
        hashDict[singleHash] = ['phpass, MD5(Wordpress), MD5(phpBB3)']
    elif singleHash.startswith('$1$'):
        hashDict[singleHash] = ['md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5']
    elif singleHash.startswith('$apr1$'):
        hashDict[singleHash] = ['md5apr1, MD5(APR), Apache MD5']
    elif singleHash.startswith('sha256$'):
        hashDict[singleHash] = ['SHA-256(Django)']
    elif singleHash.startswith('$SHA$'):
        hashDict[singleHash] = ['SHA-256(AuthMe)']
    elif singleHash.startswith('sha256$'):
        hashDict[singleHash] = ['SHA-256(Django)']
    elif singleHash.startswith('sha384$'):
        hashDict[singleHash] = ['SHA-384(Django)']
    elif singleHash.startswith('$SHA$'):
        hashDict[singleHash] = ['SHA-256(AuthMe)']
    elif singleHash.startswith('$2$') or singleHash.startswith('$2a$') or singleHash.startswith('$2y'):
        hashDict[singleHash] = ['bcrypt, Blowfish(OpenBSD)']
    elif singleHash.startswith('$5$'):
        hashDict[singleHash] = ['sha256crypt, SHA256(Unix)']
    elif singleHash.startswith('$6$'):
        hashDict[singleHash] = ['sha512crypt, SHA512(Unix)']
    elif singleHash.startswith('$S$'):
        hashDict[singleHash] = ['SHA-512(Drupal)']
    elif singleHash.startswith('{SHA}'):
        hashDict[singleHash] = ['nsldap, SHA-1(Base64), Netscape LDAP SHA']
    elif singleHash.startswith('{SSHA}'):
        hashDict[singleHash] = ['nsldaps, SSHA-1(Base64), Netscape LDAP SSHA']
    elif singleHash.startswith('{smd5}'):
        hashDict[singleHash] = ['AIX {smd5}']
    elif singleHash.startswith('{ssha1}'):
        hashDict[singleHash] = ['AIX {ssha1}']
    elif singleHash.startswith('$md5$'):
        hashDict[singleHash] = ['MD5(Sun)']
    elif singleHash.startswith('$episerver$*0*'):
        hashDict[singleHash] = ['EPiServer 6.x < v4']
    elif singleHash.startswith('$episerver$*1*'):
        hashDict[singleHash] = ['EPiServer 6.x > v4']
    elif singleHash.startswith('{ssha256}'):
        hashDict[singleHash] = ['AIX {ssha256}']
    elif singleHash.startswith('{SSHA512}'):
        hashDict[singleHash] = ['SSHA-512(Base64), LDAP {SSHA512}']
    elif singleHash.startswith('{ssha512}'):
        hashDict[singleHash] = ['AIX {ssha512}']
    elif singleHash.startswith('$ml$'):
        hashDict[singleHash] = ['OSX v10.8']
    elif singleHash.startswith('grub'):
        hashDict[singleHash] = ['GRUB 2']
    elif singleHash.startswith('sha256$'):
        hashDict[singleHash] = ['SHA-256(Django)']
    elif singleHash.startswith('sha384$'):
        hashDict[singleHash] = ['SHA-384(Django)']
    elif singleHash.startswith('0x'):
        if len(singleHash) == 34:
            hashDict[singleHash] = ['Lineage II C4']
        elif len(singleHash) < 60:
            hashDict[singleHash] = ['MSSQL(2005)']
        elif len(singleHash) < 100:
            hashDict[singleHash] = ['MSSQL(2000)']
        else:
            hashDict[singleHash] = ['MSSQL(2012)']
    elif singleHash.startswith('S:'):
        hashDict[singleHash] = ['Oracle 11g']
    elif len(singleHash) > 41 and singleHash.count(':') == 1 and singleHash[-41] == ':' and isHex(singleHash[-40:]):
        hashDict[singleHash] = ['sha1(strtolower($username).$pass),  SMF >= v1.1']
    elif singleHash.count(':') > 1:
        if singleHash.count(':') == 5:
            hashDict[singleHash] = ['NetNTLMv2', 'NetNTLMv1-VANILLA / NetNTLMv1+ESS']
        elif singleHash.count(':') == 2 and '@' not in singleHash:
            hashDict[singleHash] = ['MD5(Chap)']
        elif singleHash.count(':') == 3 or singleHash.count(':') == 6:
            hashDict[singleHash] = ['Domain Cached Credentials, mscash']
            try:
                hashDict[singleHash.split(':')[3]] = 'NTLM'
                if not singleHash.split(':')[2] == 'aad3b435b51404eeaad3b435b51404ee' and not singleHash.split(':')[2] == 'aad3b435b51404eeaad3b435b51404ee'.upper():
                    hashDict[singleHash.split(':')[2]] = 'LM'
            except Exception as e:
                pass
        elif singleHash.count(':') == 2 and '@' in singleHash:
            hashDict[singleHash] = ['Lastpass']
    elif len(singleHash) == 4:
        hashDict[singleHash] = ['CRC-16', 'CRC-16-CCITT', 'FCS-16']
    elif len(singleHash) == 8:
        hashDict[singleHash] = ['CRC-32', 'CRC-32B', 'FCS-32', 'ELF-32', 'Fletcher-32', 'FNV-32', 'Adler-32', 'GHash-32-3', 'GHash-32-5']
    elif len(singleHash) == 13:
        if singleHash.startswith('+'):
            hashDict[singleHash] = ['Blowfish(Eggdrop)']
        else:
            hashDict[singleHash] = ['descrypt, DES(Unix), Traditional DES']
    elif len(singleHash) == 16:
        if isHex(singleHash):
            hashDict[singleHash] = ['MySQL, MySQL323', 'Oracle 7-10g, DES(Oracle)', 'CRC-64', 'SAPB', 'substr(md5($pass),0,16)', 'substr(md5($pass),16,16)', 'substr(md5($pass),8,16)']
        else:
            hashDict[singleHash] = ['Cisco-PIX MD5']
    elif len(singleHash) > 16 and singleHash[-17] == ':' and singleHash.count(':') == 1:
        hashDict[singleHash] = ['DES(Oracle)', 'Oracle 10g']
    elif len(singleHash) == 20:
        hashDict[singleHash] = ['substr(md5($pass),12,20)']
    elif len(singleHash) == 24 and isHex(singleHash):
        hashDict[singleHash] = ['CRC-96(ZIP)']
    elif len(singleHash) == 35:
        hashDict[singleHash] = ['osCommerce, xt:Commerce']
    elif len(singleHash) > 40 and singleHash[40] == ':' and singleHash.count(':') == 1:
        hashDict[singleHash] = ['sha1($salt.$pass.$salt)', 'sha1(md5($pass.$salt))']
    elif len(singleHash) > 40 and singleHash.count('-') == 2 and singleHash.count(':') == 2:
        hashDict[singleHash] = ['sha1(md5($pass).$userdate.$salt)']
    elif len(singleHash) > 40 and singleHash.count(':') == 2 and len(singleHash.split(':')[1]) == 40 :
        hashDict[singleHash] = ['sha1($pass.$username.$salt)']
    elif len(singleHash) == 41 and singleHash.startswith('*') and isHex(singleHash[1:40]):
        hashDict[singleHash] = ['MySQL4.1/MySQL5']
    elif len(singleHash) == 43:
        hashDict[singleHash] = ['Cisco-IOS SHA256']
    elif len(singleHash) == 47:
        hashDict[singleHash] = ['Fortigate (FortiOS)']
    elif len(singleHash) == 48 and isHex(singleHash):
        hashDict[singleHash] = ['Oracle 11g, SHA-1(Oracle)', 'Haval-192', 'Haval-192(HMAC)' 'Tiger-192', 'Tiger-192(HMAC)', 'OSX v10.4, v10.5, v10.6']
    elif len(singleHash) == 51 and isHex(singleHash):
        hashDict[singleHash] = ['MD5(Palshop)', 'Palshop']
    elif len(singleHash) == 56 and isHex(singleHash):
        hashDict[singleHash] = ['SHA-224', 'Haval-224', 'SHA-224(HMAC)', 'Haval-224(HMAC)', 'Keccak-224', 'Skein-256(224)', 'Skein-512(224)']
    elif len(singleHash) == 65:
        hashDict[singleHash] = ['Joomla']
    elif len(singleHash) > 64 and singleHash[64] == ':':
        hashDict[singleHash] = ['SHA-256(PasswordSafe)', 'sha256(md5($salt.$pass))', 'sha256(md5($pass.$salt))', 'SHA-256(HMAC)', 'SHA-256(RuneScape)', 'sha256($salt.$pass)', 'sha256($pass.$salt)', 'Haval-256(HMAC)', 'RipeMD-256(HMAC)', 'Snefru-256(HMAC)', 'sha256(sha256($pass).$salt)']
    elif len(singleHash) == 80 and isHex(singleHash):
        hashDict[singleHash] = ['RipeMD-320', 'RipeMD-320(HMAC)']
    elif len(singleHash) == 96 and isHex(singleHash):
        hashDict[singleHash] = ['SHA-384', 'Keccak-384', 'SHA-384(HMAC)', 'sha384($salt.$pass)', 'sha384($pass.$salt)', 'Skein-512(384)', 'Skein-1024(384)']
    elif len(singleHash) == 128 and isHex(singleHash):
        hashDict[singleHash] = ['Keccak-512', 'Skein-1024(512)',  'Skein-512', 'SHA512', 'sha512($pass.$salt)', 'sha512($salt.$pass)', 'SHA-512(HMAC)', 'Whirlpool', 'Whirlpool(HMAC)', 'sha512(unicode($pass).$salt)', 'sha512($salt.unicode($pass))', 'HMAC-SHA512 (key = $pass)']
    elif len(singleHash) > 128 and singleHash[128] == ':':
        hashDict[singleHash] = ['HMAC-SHA512 (key = $salt)']
    elif len(singleHash) == 130 and isHex(singleHash):
        hashDict[singleHash] = ['IPMI2 RAKP HMAC-SHA1']
    elif len(singleHash) == 136 and isHex(singleHash):
        hashDict[singleHash] = ['OSX v10.7']
    elif len(singleHash) == 177:
        hashDict[singleHash] = ['Whirlpool(Double)']
    elif len(singleHash) == 256 and isHex(singleHash):
        hashDict[singleHash] = ['Skein-1024']
    else:
        hashDict[singleHash] = []


def identify_hash(hash_string):
    identifyHash(hash_string)
    results = []
    if len(hashDict[hash_string]):
        for value in hashDict[hash_string]:
            results.append(value)
    return results or None
