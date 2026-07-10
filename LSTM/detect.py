from calendar import firstweekday

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib  

class TestModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder=nn.LSTM(input_size=44,hidden_size=64,batch_first=True)
        self.decoder=nn.LSTM(input_size=64,hidden_size=64,batch_first=True)
        self.output_layer=nn.Linear(64,44)
    def forward(self, x):
        _,(hidden,cell)=self.encoder(x)
        hidden=hidden.squeeze(0)
        decoderInput=hidden.unsqueeze(1)
        decoderInput=decoderInput.repeat(1,windowSize,1)
        decoderOutput,_=self.decoder(decoderInput)
        reconstructed=self.output_layer(decoderOutput)
        return reconstructed

#sequencing    
windowSize=30
def createSeq(data,window):
    sequences=[]
    for i in range(len(data)-window):
        sequences.append(data[i:i+window])
    
    return np.array(sequences)


model=TestModel()
model.load_state_dict(torch.load("model.pth"))
model.eval()
threshold=torch.load("threshold.pth")
scaler=joblib.load("scaler.pkl")
#print("Threshold: ", threshold.item())

#loading dataset
df=pd.read_csv("../data/attack.csv")
df.columns=df.columns.str.strip()
labels=df["Normal/Attack"]
timestamp=df["Timestamp"]
featureNames=df.drop(columns=["Timestamp","Normal/Attack","MV101","AIT201","MV201","P201","P202","P204","MV303"]).columns.tolist()
df=df.drop(columns=["Timestamp","Normal/Attack","MV101","AIT201","MV201","P201","P202","P204","MV303"])
seq,fet=df.shape
print("Total sequences: ",seq,"and features: ",fet)

scalerData=scaler.transform(df)
x=createSeq(scalerData,windowSize)
xTensor=torch.tensor(x,dtype=torch.float32)

def attackSpecify(sensorName):
    score={
        "Flow Manipulation":0,
        "Tank Level Manipulation": 0,
        "Pressure Manipulation": 0,
        "Valve Manipulation": 0,
        "Pump Manipulation": 0,
        "Unknown": 0,
    }

    for sensor in sensorName:
        if sensor.startswith("FIT"):
            score["Flow Manipulation"]+=1
        elif sensor.startswith("LIT"):
            score["Tank Level Manipulation"]+=1
        elif sensor.startswith("PIT") or sensor.startswith("DPIT"):
            score["Pressure Manipulation"]+=1
        elif sensor.startswith("MV"):
            score["Valve Manipulation"]+=1
        elif sensor.startswith("P"):
            score["Pump Manipulation"]+=1
    return max(score,key=score.get)

with torch.no_grad():
    recon=model(xTensor)
    featureErrors=torch.mean((recon-xTensor)**2,dim=1)
    errors=torch.mean((recon-xTensor)**2,dim=(1,2))
    anomalies=torch.where(errors>threshold)[0]
    attackSeg=[]
    strt=anomalies[0].item()
    prv=anomalies[0].item()
    for seq in anomalies[1:]:
        curr=seq.item()
        if curr <= prv+5:
            prv=curr
        else:
            attackSeg.append((strt,prv))
            strt=curr
            prv=curr
    attackSeg.append((strt,prv))
    featureAnomaly=featureErrors[anomalies]
    avgFeatureError=featureAnomaly.mean(dim=0)
    print("Detected Anomalies: ",len(anomalies))
    if len(anomalies)>0:
        top=torch.topk(avgFeatureError,5)
        print("\n----Overall sensor's anomaly ranking----")
        print("Sensor\tReconstruction Error")
        topSensor=[]
        for idx in top.indices:
            sensor=featureNames[idx]
            topSensor.append(sensor)
            print(featureNames[idx],"->",avgFeatureError[idx].item())

        attack=attackSpecify(topSensor)
        print("\n----Attack Classification----")
        print("Likely Attack: ",attack)
        print("\n----Attack Segments----")
        for i ,(startSeg,endSeg) in enumerate(attackSeg,start=1):
            endRow=endSeg+windowSize-1
            print("\nAttack started row: ", startSeg)
            print("Attack ended row: ", endSeg)
            print("Start Time: ", timestamp.iloc[startSeg])
            print("End Time: ", timestamp.iloc[endSeg])
