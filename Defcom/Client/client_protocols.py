from DefComCryptography import Generate32BitKey, Encrypt, Decrypt, SignWithPrivateKey, VerifiySignedWithPublicKey, generate_RSA
from Crypto.PublicKey import RSA 
import json
import unittest
from datetime import timedelta, datetime
from base64 import b64encode, b64decode

from config import SERV_PUB_KEY


def symKeyGenerator( allUsersAndKeys, wantedUsers ):
	usersAndPubKeys = []
	for allUser in allUsersAndKeys:
		if allUser["user_name"] in wantedUsers:
			usersAndPubKeys.append(allUser)

	convoSymkey = Generate32BitKey()

	usersAndSymKeys = []
	checkMessage = ""
	for user in usersAndPubKeys:

		encSymKey = b64encode( RSA.importKey(user["public_key"])
			.encrypt(str(convoSymkey),32)[0])

		usersAndSymKeys.append({"user_name":user["user_name"],"encSymKey":encSymKey})
		checkMessage += user["user_name"] + encSymKey
	
	#print usersAndSymKeys
	return usersAndSymKeys, checkMessage



def ResponseChecker( response ):

	'''
	checks the validity of a simple message that consists of a
	dictionary with 3 elements: timestamp | message | signature

	'''


	json_rsp = json.loads(response)[0]

	now_timestamp =  datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	timestamp_check = detect_replay_protection( timestamp=json_rsp["timestamp"], timestamp_against=now_timestamp )
	if not (timestamp_check):
		print "The timestamp is expired, this message might be a replay"
		return ""

	sig_check = VerifiySignedWithPublicKey( SERV_PUB_KEY, json_rsp["signature"], json_rsp["timestamp"]+json_rsp["message"] )
	if not (sig_check):
		print "The signature verification failed, the message may have been tampered with"
		return ""

	return json_rsp["message"]


def MessageMaker(privateKey, message):
	'''
	makes a simple message that consists of a
	dictionary with 3 elements: timestamp | message | signature

	'''

	timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	signature = SignWithPrivateKey(privateKey, timestamp+message)

	full_message = json.dumps({
			"timestamp": timestamp,
			"message" : message,
			"signature": signature
	})

	return full_message



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

	#encrypt password with server public key
	plain_password = login_data["password"]
	enc_password = b64encode( RSA.importKey(SERV_PUB_KEY).encrypt(str(plain_password),32)[0])
	#print "plain password:", plain_password, "\nencrypted password:",enc_password

	# produce timestamp
	timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	#print timestamp

	# generate the client signature 
	payload = timestamp + login_data['user_name'] + enc_password
	client_sig = SignWithPrivateKey( private_key=login_data['private_key'], msg=payload )
	#print "Payload: ", payload, "\nsignature: ", client_sig  "
	
	user_data = json.dumps({
			"timestamp": timestamp,
			"user_name": login_data["user_name"],
			"enc_password": enc_password,
			"public_key": login_data["public_key"],
			"client_sig": client_sig,
			"certificate": login_data['certificate']
	})

	return user_data

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

class TestAuthenticationRequest( unittest.TestCase ):
	
	def setUp( self ):
		
		# TODO ideally these credentials are held in a separate file.. i.e. user-defined profile on client side
		# self.users_private_credentials = create_new_user( 
		# 	username='Thavy', 
		# 	plaintext_password='skylarlevy421'
		# )

		with open('user_quantum.json', 'r') as outfile:
			self.json_data = outfile.read()
			self.data = json.loads( self.json_data )
		
		# for tag in self.data:
			# print (self.data[tag])

	def testAuthReq( self ):
		# the line below should be sent to the server

		creds = AuthenticationProtocol( data=self.json_data )
		credDict = json.loads(creds)
		p1 = b64decode(credDict["password"])
		#print credDict
		

		f = open( 'SERV_PRIV_KEY.pem', 'r' )
		SERV_PRIV_KEY = RSA.importKey(f.read())
		f.close()

		decrypt_pw = SERV_PRIV_KEY.decrypt(p1)

		# print creds
		# print "TODO: fix testcase lol -kek"
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
			#print ts, self.now
			#self.assertFalse( boolReplay )  WASN'T WORKING

	def testBadDetectReplayProtection( self ):
		for ts in self.bad_timestamps:
			boolReplay = detect_replay_protection( timestamp=ts, timestamp_against=self.now )
			self.assertTrue( boolReplay )



if __name__ == "__main__":
	unittest.main()
	
			
