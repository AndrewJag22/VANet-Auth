import hashlib
import time
import random


class Base:
    def __init__(self):
        pass

    @staticmethod
    def hash(hash_input):
        '''
        Computes a 160bit hash value for the given input
        :param hash_input: String to be hashed
        :return: 160bit hash value
        '''
        hash_input = hash_input.encode('utf-8')
        return hashlib.sha1(hash_input).hexdigest()

    @staticmethod
    def sxor(x, y):
        '''
        String XOR
        :return: 160bit XOR of 2 strings
        '''
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(x, y))

    @staticmethod
    def generate_random_nonce():
        '''
        :return: A random 160bit random nonce
        '''
        return str(random.randint(0, 10000000000000000))

    @staticmethod
    def generate_160bit_key():
        hash_input = Base.generate_random_nonce().encode('utf-8')
        return hashlib.sha1(hash_input).hexdigest()

    @staticmethod
    def generate_current_timestamp():
        # Returns time since epoch (UTC)
        return str(int(time.time()))

    @staticmethod
    def hex_transform(x):
        return ":".join("{:02x}".format(ord(c)) for c in x)


class TrafficAuthority(Base):
    def __init__(self, id):
        Base.__init__(self)
        self.id = id
        self.rsu_list = []
        self.registered_cars = {}
        self.X, self.X_dash = self.generate_1024bit_secret_keys()

    def add_rsu(self, rsu):
        rsu.register(self)
        self.rsu_list.append(rsu)

    def register_vehicle(self, vehicle_id, user_id, masked_password_xor_k, registration_time):
        self.registered_cars[vehicle_id] = registration_time
        pseudo_id = self.hash(vehicle_id + self.X)
        a1 = self.hash(pseudo_id + self.X)
        a2 = self.hash(pseudo_id + a1 + self.id)
        x = self.hash(self.id + self.X)
        x_dash = self.hash(self.id + self.X_dash)
        y1 = self.sxor(self.sxor(x, a2), masked_password_xor_k)
        y2 = self.sxor(self.sxor(x_dash, a2), masked_password_xor_k)
        k_v = self.generate_160bit_key()
        temporal_credential = self.hash(k_v + str(registration_time) + user_id)
        return pseudo_id, temporal_credential, self.id, y1, y2, a1, a2

    # Need to improve this function
    def generate_1024bit_secret_keys(self):
        x1 = self.sha512(self.generate_random_nonce())
        x2 = self.sha512(self.generate_random_nonce())
        x1_dash = self.sha512(self.generate_random_nonce())
        x2_dash = self.sha512(self.generate_random_nonce())
        return x1 + x2, x1_dash + x2_dash

    @staticmethod
    def sha512(hash_input):
        hash_input = hash_input.encode('utf-8')
        return hashlib.sha512(hash_input).hexdigest()


class RSU(Base):
    def __init__(self, id):
        Base.__init__(self)
        self.id = id
        self.pseudo_id = ''
        self.time_dependent_id = ''
        self.secret_key = ''
        self.registration_time = ''
        self.traffic_authority = ''

        # TODO: Implement GF(p) polynomial share via Blundo et al
        self.polynomial_share = ''

    def register(self, traffic_authority):
        self.registration_time = str(time.time())
        x, x_dash = traffic_authority.X, traffic_authority.X_dash
        self.pseudo_id = self.hash(self.id + x_dash)
        self.secret_key = self.hash(traffic_authority.id + x_dash)
        self.time_dependent_id = self.hash(traffic_authority.id + self.registration_time + x_dash)


class Vehicle(Base):
    def __init__(self, user_id, id, password, r, k):
        Base.__init__(self)
        self.registration_time = ''
        self.user_id = user_id
        self.id = id
        self.password = password
        self.r = r
        self.k = k
        self.pseudo_id_dash = ''
        self.temporal_credential_dash = ''
        self.traffic_authority_id_dash = ''
        self.b = ''
        self.y = ''
        self.y_dash = ''
        self.a1_dash = ''
        self.a4 = ''

    def request_registration(self, traffic_authority):
        self.registration_time = time.time()
        masked_password = self.hash(self.password + self.r)
        masked_password_xor_k = self.sxor(masked_password, self.k)
        pseudo_id, temporal_credential, traffic_authority_id, y1, y2, a1, a2 = traffic_authority.register_vehicle(
            self.id, self.user_id, masked_password_xor_k, self.registration_time)
        self.b = self.sxor(self.hash(self.password + self.id), self.r)
        self.a1_dash = self.sxor(a1, self.hash(self.id + self.r))
        self.traffic_authority_id_dash = self.sxor(self.hash(self.id + self.r), traffic_authority.id)
        a3 = self.hash(self.id + masked_password + traffic_authority.id + a1)
        self.a4 = self.hash(a3 + a2)
        self.pseudo_id_dash = self.sxor(pseudo_id, self.hash(self.password + self.id + self.r))
        self.temporal_credential_dash = self.sxor(temporal_credential, self.hash(self.password + self.r))
        self.y = self.sxor(y1, self.k)
        self.y_dash = self.sxor(y2, self.k)
