from scapy.all import *

modbus_func = {
    1: "Read coils",
    2: "Read discrete inputs",
    3: "Read holding registers",
    4: "Read Input registers",
    5: "Write single coil",
    6: "Write single register",
    15: "Write multiple coils",
    16: "Write multiple registers"
}

READ_CODES = [1,2,3,4]
WRITE_CODES = [5,6,15,16]


def parse(pkt):

    if TCP in pkt:
        if pkt[TCP].sport==502 or pkt[TCP].dport==502:
            if Raw in pkt:
                payload=bytes(pkt[Raw].load)
                if len(payload) >= 10:
                    funcCode=payload[7]
                    register=int.from_bytes(payload[8:10],byteorder="big")

                    if funcCode >= 128:
                        actual_fc=funcCode - 128
                        name=modbus_func.get(actual_fc,"Unknown")
                        print(f"[EXCEPTION] {name}")

                    else:
                        name=modbus_func.get(funcCode,"Unknown")
                        if funcCode in READ_CODES:
                            print(f"[READ] {name} | Register {register}")
                        elif funcCode in WRITE_CODES:
                            print(f"⚠️ ALERT: Modbus Write Occurs ({name}) from {pkt[IP].src}")
                        else:
                            print(f"[UNKNOWN] FC={funcCode}")
                    return register
    return None