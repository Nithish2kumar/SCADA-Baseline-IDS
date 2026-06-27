import csv
import os
import time

registers = {
    "TankLevel": 20,
    "Temperature": 30,
    "Pressure": 60,
    "FlowRate": 0,
    "PumpState": 0,
    "ValveState": 0
}

registers["PumpState"] = 1
file_exists = os.path.isfile(
    "data/sensor_data.csv"
)

f = open(
    "data/sensor_data.csv",
    "a",
    newline=""
)

writer = csv.writer(f)

if not file_exists:
    writer.writerow([
        "timestamp",
        "TankLevel",
        "Temperature",
        "Pressure",
        "FlowRate",
        "PumpState",
        "ValveState"
    ])
while True:

    if registers["TankLevel"] <= 20:
        registers["PumpState"] = 1
        registers["ValveState"] = 0

    elif registers["TankLevel"] >= 80:
        registers["PumpState"] = 0
        registers["ValveState"] = 1

    if registers["PumpState"]:
        registers["FlowRate"] = 40
        registers["TankLevel"] += 1

    elif registers["ValveState"]:
        registers["FlowRate"] = 0
        registers["TankLevel"] -= 1

    registers["Pressure"] = (
        50 + registers["TankLevel"] // 2
    )

    registers["Temperature"] = (
        30 + registers["TankLevel"] // 10
    )
    writer.writerow([
    time.time(),
    registers["TankLevel"],
    registers["Temperature"],
    registers["Pressure"],
    registers["FlowRate"],
    registers["PumpState"],
    registers["ValveState"]
])

    f.flush()
    print(registers)

    time.sleep(1)


