from models import *
import tkinter
import matplotlib.pyplot as mp

VEHICLE_COUNT = 1
RSU_COUNT = 6
TRAFFIC_AUTHORITY_ID = "TA-001"

if __name__ == '__main__':

    times = []

    for j in range(100, 1000, 100):

        ta = TrafficAuthority(TRAFFIC_AUTHORITY_ID)

        user_ids = ['user ' + str(i) for i in range(j)]
        init = time.time()

        for i in range(j):
            passwd = Base.generate_random_nonce()
            r = Base.generate_160bit_key()
            k = Base.generate_160bit_key()
            vehicle = Vehicle(user_ids[i], str(i), passwd, r, k)
            vehicle.request_registration(ta)

        fin = time.time()
        print("Time for", j, "vehicles:", fin - init, "Hashed Computed:", 17 * j, "\tTime/Hash:",
              (fin - init) / (17 * j))
        times.append(fin - init)
