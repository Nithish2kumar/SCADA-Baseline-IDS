from scapy.all import *

MODBUS_FUNCTIONS = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers"
}

RISK_SCORE = {
    1: 1,
    2: 1,
    3: 1,
    4: 1,
    5: 5,
    6: 6,
    15: 8,
    16: 10
}

def risky(score):
    if score>=10:
        return "CRITICAL"
    elif score>=7:
        return "HIGH"
    elif score>=4:
        return "MEDIUM"
    return "LOW"

def alerting(src_ip, funcCode, addr):
    if funcCode is None:
        return

    if funcCode not in MODBUS_FUNCTIONS:
        return
    
    
    funcName=MODBUS_FUNCTIONS.get(funcCode,"Unknown Function")
    score=RISK_SCORE.get(funcCode,1)
    level=risky(score)
    print("\n==============================")
    print("SCADA IDS ALERT")
    print("==============================")
    print(f"Source      : {src_ip}")
    print(f"Function    : {funcName}")
    print(f"Address     : {addr}")
    print(f"Risk Score  : {score}")
    print(f"Risk level  : {level}")
    print("==============================\n")