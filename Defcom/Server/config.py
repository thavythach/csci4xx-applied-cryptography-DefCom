from Crypto.PublicKey import RSA 

# SERV KEY
f = open( 'SERV_PRIV_KEY.pem', 'r' )
SERV_PRIV_KEY = RSA.importKey(f.read())
f.close()

f = open( 'SERV_PUB_KEY.pem', 'r' )
SERV_PUB_KEY = RSA.importKey(f.read())
f.close()

print SERV_PRIV_KEY, SERV_PUB_KEY