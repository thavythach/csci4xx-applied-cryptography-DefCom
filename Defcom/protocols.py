from DefComCryptography import Generate32BitKey, Encrypt, Decrypt, SignSignature, generate_RSA
from Crypto.PublicKey import RSA 
import json
import unittest
import datetime


SERV_KEY = RSA.generate(1024, e=65537) # TODO: SHOULD BE IN A GLOBAL CONFIG

def AuthenticationProtocol( data ):
	'''
	Authentication Protocol to produce a encrypted set of data based of the username, plaintext password, and user's public key on the client side.

	Keyword Arguments:
	login_data - json object: username, password, user's pub key

	Return:
	user_data - json object: timestamp, username, encrypted password, user's public key, client's signature, and client's certificate
	'''

	# turn into parseable data
	login_data = json.loads( data )
	
	# produce a timestamp
	timestamp = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")

	# retrieve password
	plain_password = login_data["password"]
	
	# generate a 32 bit symmetric key 
	sym_key = Generate32BitKey()

	# import serv key
	serv_pub = SERV_KEY.publickey()

	# encrypt the password
	password = Encrypt( _buffer=plain_password, keystring=sym_key )

	# what's the young payload (signature msg)
	payload = timestamp+"|"+login_data["user_name"]+"|"+password

	# encrypt sym_key with server's public key
	enc_sym_key = serv_pub.encrypt( payload.encode('utf-8'), 32 )

	# generate the client signature 
	client_sig = SignSignature( private_key=login_data['private_key'], msg=payload )
	
	user_data = json.dumps({
			"timestamp": timestamp,
			"user_name": login_data["user_name"],
			"password": password,
			"public_key": login_data["public_key"],
			"enc_sym_key": enc_sym_key,
			"client_sig": client_sig,
			"certificate": 43 # TODO FIX ..... it's just 43 right now
	})

# TODO move this into DefComCryptography or somewhere else...
def create_new_user( username, plaintext_password ):
	'''

	RETURNS A JSON OBJECT of credentials the user ONLY HAS
	'''
	client_priv, client_pub = generate_RSA()
	
	cert = Generate32BitKey()
	# print( cert )
	return json.dumps({
		"user_name": username,
		"password": plaintext_password,
		"public_key": client_pub,
		"private_key": client_priv,
		"certificate":  123# TODO fix cert.....
	})


class TestAuthenticationRequest( unittest.TestCase ):
	
	def setUp( self ):
		
		# TODO ideally these credentials are held in a separate file.. i.e. user-defined profile on client side
		self.users_private_credentials = create_new_user( 
			username='Thavy', 
			plaintext_password='skylarlevy421'
		)

	def testAuthReq( self ):
		# the line below should be sent to the server
		users_encrypted_credentials = AuthenticationProtocol( data=self.users_private_credentials )
		# print users_encrypted_credentials
	
if __name__ == "__main__":
	unittest.main()