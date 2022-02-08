from rich import print


#want to reimplement something like Max's project for the requests module -> https://medium.com/cu-cyber/impersonating-ja3-fingerprints-b9f555880e42


# simple tweaks like those found in this link can alter the hash but not change attribution to a different TLS config; useful for bypassing a very specific ja3 hash  https://stackoverflow.com/questions/32650984/why-does-python-requests-ignore-the-verify-parameter/32651967#32651967

# import requests
# requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':RC4-SHA' # changes the md5sum but not overall python request attribution
# requests.get('https://ja3er.com/json')

# https://stackoverflow.com/questions/40373115/how-to-select-specific-the-cipher-while-sending-request-via-python-request-modul
# this link is the source of the below block of code. 
# the context = create_urllib3_context(ciphers=CIPHERS) line is of interest because you can pass additional args to further mimic another TLS config. 
# https://urllib3.readthedocs.io/en/latest/reference/urllib3.util.html#urllib3.util.create_urllib3_context
# most of the params present themselves as enums so random numbers might just work to evade blocking of bots. 
# carefully crafted config to emulate something else. 


import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import ssl_
import ssl

# This is the 2.11 Requests cipher string, containing 3DES.
# CIPHERS = (
#     'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
#     'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
#     '!eNULL:!MD5'
# )
CIPHERS = (
    'ECDH+HIGH:ECDH+AES256:'
)
TLS_min = -1
TLS_max = 0

def get_ctx():
	ctx:ssl.SSLContext = ssl.create_default_context()
	# ctx.set_ciphers("ECDHE-RSA-AES128-SHA256")
	# ctx.set_ecdh_curve("prime256v1")
	ctx.set_ciphers("ECDHE-RSA-AES128-SHA256")
	ctx.set_ecdh_curve("prime256v1")

	return ctx


class CustomeJA3Adapter(HTTPAdapter):
    """
    A TransportAdapter that re-enables 3DES support in Requests.
    """
    def init_poolmanager(self, *args, **kwargs):
        context = get_ctx()
        kwargs['ssl_context'] = context
        return super(CustomeJA3Adapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = get_ctx()
        kwargs['ssl_context'] = context
        return super(CustomeJA3Adapter, self).proxy_manager_for(*args, **kwargs)

s = requests.Session()
s.headers['User-Agent'] = "realuseragent"
s.mount('https://ja3er.com', CustomeJA3Adapter())
r = s.get('https://ja3er.com/json')
print(r.text)