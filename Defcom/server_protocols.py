from DefComCryptography import Generate32BitKey, Encrypt, Decrypt, SignSignature, generate_RSA
from Crypto.PublicKey import RSA 
import json
import unittest
from datetime import timedelta, datetime


def AuthenticationConfrimation( user_data ):

	user_creds = json.loads(user_data)
	detect_replay_protection(user_creds["timestamp"])

	username = user_creds["user_name"]

	#TODO: open up users file and get pw for the given username
	#also get the public key (ca_pub_key) of the CA

	user_pub_key_check = decrypt(_buffer=user_creds["certificate"], keystring=ca_pub_key)

	if not (user_pub_key_check == ):
		return "the public key was not signed properly was not correct"





	if not (user_creds["password"] == correct_password):
		return "the password was not correct"
	





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



class TestAuthenticationConfrimation( unittest.TestCase ):

	def setUp( self ):
		self.users_private_credentials = create_new_user( 
			username='Thavy', 
			plaintext_password='skylarlevy421'
		)

	def testAuthConf( self ):
		creds = AuthenticationProtocol( data=self.users_private_credentials )
		creds_dict = json.loads(creds)

		#todo authenticate time stamp


