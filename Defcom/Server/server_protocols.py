from DefComCryptography import Generate32BitKey, Encrypt, Decrypt, SignSignature, VerifiySignature, generate_RSA
from Crypto.PublicKey import RSA 
import json
import unittest
from datetime import timedelta, datetime

from config import SERV_PRIV_KEY, SERV_PUB_KEY


def AuthenticationConfirmation( user_name, password, public_key, timestamp, now_timestamp, enc_sym_key, certificate, client_sig ):
	'''
	Returns 5-tuple of symmetric-key, if replay attack was detected, certificate was signed correctly, signature signed perfectly, and encrypted password.

	:params...:
	'''
	sym_key = None
	print timestamp, now_timestamp
	boolReplay = detect_replay_protection( timestamp=timestamp, timestamp_against=now_timestamp ) 
	goodCert = False
	pw = password

	print boolReplay
	
	# if true decompose msg, else return False
	msg = timestamp + public_key + password
	print public_key
	print client_sig
	print timestamp
	ver_check = VerifiySignature( public_key, client_sig, msg )
	print ver_check
	
	if ver_check:
		pw = password
		serv_pub = SERV_PUB_KEY.publickey()
		sym_key = serv_pub.decrypt( enc_sym_key )

		# PLACEHOLDER FOR SKYLAR...TO FIX
		goodCert = True
		'''
		user_pub_key_check = decrypt(_buffer=user_creds["certificate"], keystring=ca_pub_key)

		if not (user_pub_key_check == ):
			return "the public key was not signed properly was not correct"
		'''
	else:
		pass

	print pw
	print sym_key

	return ( sym_key, boolReplay, goodCert, ver_check, pw )

'''
def AuthenticationConfrimation( user_data ):

	user_creds = json.loads(user_data)
	detect_replay_protection(user_creds["timestamp"])

	username = user_creds["user_name"]

	#TODO: open up users file and get pw for the given username
	#also get the public key (ca_pub_key) of the CA

	





	if not (user_creds["password"] == correct_password):
		return "the password was not correct"
	


'''


def detect_replay_protection( timestamp, timestamp_against=datetime.now(), t=30 ):
	'''
	Tells us whether or not the message was a valid message given 30 seconds

	Keyword Arguments:
	timestamp - client/server timestamp
	t - time available: default 30 seconds
	'''

	dt_obj = datetime.strptime( timestamp, '%Y-%m-%d %H:%M:%S' ) 
	dta_obj = datetime.strptime( timestamp_against, '%Y-%m-%d %H:%M:%S' ) 

	if dt_obj <= dta_obj-timedelta( seconds=-t ):
		return True
	return False


class TestAuthenticationConfrimation( unittest.TestCase ):

	def setUp( self ):'''
		with open('user_quantum.json', 'r') as outfile:
			self.json_data = outfile.read()
			self.data = json.loads( self.json_data )
		
		creds = client_protocols.AuthenticationProtocol( data=self.json_data )

		for c in creds:
			print c, creds[c]'''

	def testAuthConf( self ):
			
		'''
		AuthenticationConfirmation( 
			user_name=creds['user_name'], 
			password=creds['password'], 
			public_key=creds['public_key'], 
			timestamp=creds['timestamp'], 
			now_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
			enc_sym_key=creds['enc_sym_key'], 
			certificate=creds['certificate'], 
			client_sig=creds['client_sig']
		 )'''

if __name__ == "__main__":
	unittest.main()