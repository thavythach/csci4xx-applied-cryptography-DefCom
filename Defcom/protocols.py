from DefComCryptography import Generate32BitKey, Encrypt, Decrypt, SignSignature, generate_RSA
from Crypto.PublicKey import RSA 
import json
import unittest
from datetime import timedelta, datetime



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
	timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
	enc_sym_key = serv_pub.encrypt( payload.encode('utf-8'), 32 )[0].decode('unicode-escape')

	# generate the client signature 
	client_sig = SignSignature( private_key=login_data['private_key'], msg=payload )
	
	user_data = json.dumps({
			"timestamp": timestamp,
			"user_name": login_data["user_name"],
			"password": password,
			"public_key": login_data["public_key"],
			"enc_sym_key": enc_sym_key,
			"client_sig": client_sig,
			"certificate": login_data['certificate'] # TODO FIX ..... it's just 43 right now
	})

	return user_data

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
		"certificate":  123 # TODO fix cert.....
	})

def detect_replay_protection( timestamp, timestamp_against=datetime.now(), t=30 ):
	'''
	Tells us whether or not the message was a valid message given 30 seconds

	Keyword Arguments:
	timestamp - client/server timestamp
	t - time available: default 30 seconds
	'''

	dt_obj = datetime.strptime( timestamp, '%Y-%m-%d %H:%M:%S' ) 
	if dt_obj <= timestamp_against-timedelta( seconds=t ):
		return True
	return False

class TestAuthenticationRequest( unittest.TestCase ):
	
	def setUp( self ):
		
		# TODO ideally these credentials are held in a separate file.. i.e. user-defined profile on client side
		self.users_private_credentials = create_new_user( 
			username='Thavy', 
			plaintext_password='skylarlevy421'
		)

	def testAuthReq( self ):
		# the line below should be sent to the server
		creds = AuthenticationProtocol( data=self.users_private_credentials )
		print creds
		# self.assertTrue( creds['timestamp']  )
		# print users_encrypted_credentials
	
class TestReplayProtection( unittest.TestCase ):
	
	def setUp( self ):
    		
		self.now = datetime.now()
		self.timestamps = [
			( self.now + timedelta(seconds = -20)).strftime("%Y-%m-%d %H:%M:%S"),
			( self.now + timedelta(seconds = -10)).strftime("%Y-%m-%d %H:%M:%S"),
			( self.now + timedelta(seconds = -5)).strftime("%Y-%m-%d %H:%M:%S"),
			( self.now + timedelta(seconds = -1)).strftime("%Y-%m-%d %H:%M:%S"),
		]

		self.bad_timestamps = [
			( self.now + timedelta(seconds = -30)).strftime("%Y-%m-%d %H:%M:%S"),
			( self.now + timedelta(seconds = -40)).strftime("%Y-%m-%d %H:%M:%S"),
		]
		
	def testGoodDetectReplayProtection( self ):
		for ts in self.timestamps:
			boolReplay = detect_replay_protection( timestamp=ts, timestamp_against=self.now )
			self.assertFalse( boolReplay )

	def testBadDetectReplayProtection( self ):
		for ts in self.bad_timestamps:
			boolReplay = detect_replay_protection( timestamp=ts, timestamp_against=self.now )
			self.assertTrue( boolReplay )


if __name__ == "__main__":
	unittest.main()
	
			
