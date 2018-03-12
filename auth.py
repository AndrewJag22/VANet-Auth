from models import *
import matplotlib.pyplot as mp

VEHICLE_COUNT = 1
RSU_COUNT = 6
TRAFFIC_AUTHORITY_ID = "TA-001"


def simulate(vehicles, sim_size, hash_size):
    Base.hash_size = hash_size
    times = []
    for i in range(sim_size):
        init = time.time()
        for j in range(sim_size):
            if i != j:
                vehicles[i].v2v_precompute(vehicles[j])
        fin = time.time()
        times.append(fin - init)

    return times


if __name__ == '__main__':

    sim_size = 100

    ta = TrafficAuthority(TRAFFIC_AUTHORITY_ID)

    user_ids = ['user' + str(i) for i in range(sim_size)]
    passwords = []
    vehicles = []

    for i in range(sim_size):
        password = Base.byte_to_string(Base.generate_random_nonce(Base.hash_size))
        passwords.append(password)
        r = Base.generate_key(Base.hash_size)
        k = Base.generate_key(Base.hash_size)
        vehicle = Vehicle(user_ids[i], str(i), password, r, k)
        vehicles.append(vehicle)
        vehicle.request_registration(ta)
        vehicle.vehicle_authenticate(str(i), password)
        print("Vehicle", i, "was registered and authenticated")

    print("All 10 vehicles registered!")

    times1 = simulate(vehicles, sim_size, 160)
    times2 = simulate(vehicles, sim_size, 256)
    times3 = simulate(vehicles, sim_size, 512)

    ticks = [i for i in range(sim_size)]

    mp.plot(ticks, times1)
    mp.plot(ticks, times2)
    mp.plot(ticks, times3)
    mp.savefig('plots/auth_160vs256vs512.png')
