import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
from collections import deque

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
    
windowSize=30
model=TestModel()
model.load_state_dict(torch.load("model.pth"))
model.eval()
threshold=torch.load("threshold.pth")
scaler=joblib.load("scaler.pkl")
print("Threshold: ",threshold.item())

df=pd.read_csv("data/attack.csv")
df.columns=df.columns.str.strip()
df=df.drop(columns=["Timestamp","Normal/Attack","MV101","AIT201","MV201","P201","P202","P204","MV303"])
print("Dataset Shape: ",df.shape)

scalerData=scaler.transform(df)
buffer=deque(maxlen=windowSize)

anomaly=[]
for i,row in enumerate(scalerData):
    buffer.append(row)
    if len(buffer)<windowSize:
        continue

    x=np.array(buffer)
    x=x.reshape(1,windowSize,44)
    xTensor=torch.tensor(x,dtype=torch.float32)

    with torch.no_grad():
        recon=model(xTensor)
        error=torch.mean((recon-xTensor)**2,dim=(1,2)).item()
        if error>threshold.item():
            anomaly.append(i)

print("Anomaly summary:")
print("Total anomalies: ",len(anomaly))
if len(anomaly)>0:
    print("First anomaly row: ",anomaly[0])
    print("Last anomaly row: ",anomaly[-1])
    