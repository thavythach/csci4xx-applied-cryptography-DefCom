class User:
    def __init__(self, user_name, password, public_key, timestamp, certificate, client_sig):
        self.user_name = user_name
        self.password = password
        self.public_key = public_key
        self.timestamp = timestamp
        self.certificate = certificate
        self.client_sig = client_sig

    def __str__(self):
        return "Username: " + self.user_name + " password: " + self.password