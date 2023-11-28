import os
import argparse
import ipaddress
import re

class Validation:
    @staticmethod
    def validate_vt_api_key(vt_api_key: str):
        pattern = re.compile(r'^[0-9a-z]{64}$')
        
        if vt_api_key == None:
            print('Virus Total API key is not provided. Please provide API key with [ -k ] option. Or firstly save it with [ -sk ] option.')
            return False
        
        if pattern.match(vt_api_key):
            return True
        
        print('Virus Total API key has wrong format. Key consists of 64 digits or lower case letters') 
        return False
    
    @staticmethod
    def validate_file(file):
        if not os.path.exists(file):
            raise argparse.ArgumentTypeError(f'{file} does not exist')
        
        return file

    @staticmethod
    def validate_ip(ip: str):
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    @staticmethod
    def validate_domain(domain: str):
        pattern = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*(?<!-)$')
        if pattern.match(domain):
            return True
        else:
            return False

    @staticmethod
    def validate_url(url: str):
        url_pattern = re.compile(
            # r"^(?:(http(s)?|gopher|ftp):\/\/)?[\w.-]+(?:\.[\w.-]+)+[\w\-._~:/?#[\]@!$&'()*+,;=.]+$"
            r'https?://|ftp://|file://|mailto:|tel:|news:|data:|irc://|ircs://|gopher://|nntp://|snews://|svn\+ssh://|svn://|ws://|wss://|rtsp://|rtmp://|mms://|ed2k://|webcal://|feed:|ldap://|ldaps://|dict://|sips?:|bitcoin:|ethereum:|magnet:|[a-zA-Z0-9\.\-]+://[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)'
        )

        # Example usage
        if url_pattern.match(url):
            return True
        
        return False

    @staticmethod
    def validate_hash(hash: str):
        sha256 = re.compile(r"^[a-fA-F0-9]{64}$")
        sha1 = re.compile(r"^[a-fA-F0-9]{40}$")
        md5 = re.compile(r"^[a-fA-F0-9]{32}$")
        
        if sha256.match(hash):
            print(f'{hash} recognized as SHA-256')
            return True
        if sha1.match(hash):
            print(f'{hash} recognized as SHA-1')
            return True
        if md5.match(hash):
            print(f'{hash} recognized as MD5')
            return True
        
        return False