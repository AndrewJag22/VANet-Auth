from models import *
import tkinter
import matplotlib.pyplot as mp

VEHICLE_COUNT = 1
RSU_COUNT = 6
TRAFFIC_AUTHORITY_ID = "TA-001"


def simulate(iterations, skips, hash_size):
    print("------ Simulation for key size " + str(hash_size) + " begins -------")

    times = []

    # Set hash_size value
    Base.hash_size = hash_size
    ticks = [j for j in range(1, iterations, skips)]

    for j in range(1, iterations, skips):

        ta = TrafficAuthority(TRAFFIC_AUTHORITY_ID)

        user_ids = ['user ' + str(i) for i in range(j)]
        init = time.time()

        for i in range(j):
            passwd = Base.byte_to_string(Base.generate_random_nonce(Base.hash_size))
            r = Base.generate_key(Base.hash_size)
            k = Base.generate_key(Base.hash_size)
            vehicle = Vehicle(user_ids[i], str(i), passwd, r, k)
            vehicle.request_registration(ta)
            vehicle.vehicle_authenticate(str(i),passwd)

        fin = time.time()
        print("Time for", j, "vehicles:", fin - init, "Hashed Computed:", 17 * j, "\tTime/Hash:",
              (fin - init) / (17 * j))
        times.append(fin - init)

    print("------ Simulation for key size " + str(hash_size) + " ends -------")
    return ticks, times


if __name__ == '__main__':
    ticks1, times1 = simulate(100, 1, 160)
    ticks2, times2 = simulate(100, 1, 256)
    ticks3, times3 = simulate(100, 1, 512)

    mp.plot(ticks1, times1)
    mp.plot(ticks2, times2)
    mp.plot(ticks3, times3)
    mp.show()
