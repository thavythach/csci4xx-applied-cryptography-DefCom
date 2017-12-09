
class User:
    def __init__(self, user_name, password, public_key, certificate):
        self.user_name = user_name
        self.password = password
        self.public_key = public_key
        self.certificate = certificate
    def __str__(self):
        return "Username: " + self.user_name + " password: " + self.password