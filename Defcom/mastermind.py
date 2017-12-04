from DefComCryptography import generate_RSA, Generate32BitKey
import json
import os

def create_new_user( username, plaintext_password ):
	'''
	RETURNS A JSON OBJECT of credentials the user ONLY HAS
	'''
	client_priv, client_pub = generate_RSA()
	
	cert = Generate32BitKey()
	# print( cert )
	return {
		"user_name": username,
		"password": plaintext_password,
		"public_key": client_pub,
		"private_key": client_priv,
		"certificate":  cert.decode('unicode-escape') 
		# encrypted_hash of the public_key and encrypted with the CA's private key
	}

if __name__ == "__main__":
	
	user_pass = [
		('bill', 'gates'),
		('steve', 'jobs'),
		('skylar', 'levey'),
		('thavy', 'thach'),
		('classical', 'cryptography'),
		('quantum', 'cryptography')
	]

	for user, pw in user_pass:
		data = create_new_user( username=user , plaintext_password=pw )

		with open('user_' + user + ".json", 'w') as outfile:
			json.dump(data, outfile)
	
	# TODO put in a user folder
	# for idx in range(0,10):
	# cwd = os.getcwd()
	# print( cwd )
	# client = cwd+'/client'
	# server = cwd+'/server'

	# if not os.path.exists(client):
	#     os.makedirs(client)
	
	# os.fchdir(client)

	# for user in range(0,5):
	# 	creds = create_new_user( "Shirley_"+user, "bad_password_"+user )
		