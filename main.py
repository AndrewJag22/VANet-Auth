from models import *

VEHICLE_COUNT = 10
RSU_COUNT = 6
TRAFFIC_AUTHORITY_ID = "TA-001"

if __name__ == '__main__':

    ta = TrafficAuthority(TRAFFIC_AUTHORITY_ID)

    for i in range(VEHICLE_COUNT):
        passwd = Base.generate_random_nonce()
        r = Base.generate_160bit_key()
        k = Base.generate_160bit_key()
        print("Vehicle ID", i)
        print("r:", r)
        print("k:", k)
        vehicle = Vehicle(str(i), passwd, r, k)
        vehicle.request_registration(ta)
        print("Temp Id", vehicle.temporal_credential_dash)
        print("Pseudo Id", vehicle.pseudo_id_dash)
        print("=====================================")
