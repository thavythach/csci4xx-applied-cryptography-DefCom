from DefComCryptography import Generate32BitKey, Encrypt, Decrypt, SignWithPrivateKey, VerifiySignedWithPublicKey
from Crypto.PublicKey import RSA
import json
import unittest
from datetime import timedelta, datetime
from base64 import b64encode, b64decode 

from config import SERV_PRIV_KEY, SERV_PUB_KEY


def AuthenticationConfirmation( timestamp, now_timestamp, user_name, enc_password, public_key, client_sig, certificate ):
	'''
	Returns 5-tuple of symmetric-key, if replay attack was detected, certificate was signed correctly, signature signed perfectly, and encrypted password.

	:params...:
	'''

	#first check the timestamp
	#print timestamp, now_timestamp
	timestamp_check = detect_replay_protection( timestamp=timestamp, timestamp_against=now_timestamp )
	if not (timestamp_check):
		print "The timestamp is expired, this message might be a replay"
		return

	#get the CA's public key
	f = open( 'CA_PUB_KEY.pem', 'r' )
	CA_PUB_KEY = f.read()
	f.close()

	#check the certificate to make sure the public key is legitimate
	cert_check = VerifiySignedWithPublicKey( CA_PUB_KEY, certificate, user_name+public_key )
	if not (cert_check):
		print "The certificate verification failed, the public key may not be legitimate"
		return
	print "certificate verified"

	#check the signature with the verified public key
	sig_check = VerifiySignedWithPublicKey( public_key, client_sig, timestamp+user_name+enc_password )
	if not (sig_check):
		print "The signature verification failed, the message may have been tampered with"
		return
	print "signature verified"

	#decode password and then look for user in the database
	#print "recieved enc_password: ", enc_password

	password = RSA.importKey(SERV_PRIV_KEY).decrypt( b64decode(enc_password) )
	print "password decrypted"

	return password


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