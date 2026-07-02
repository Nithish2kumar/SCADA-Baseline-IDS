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
windowSize=20
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
print("Threshold: ", threshold.item())

#loading dataset
df=pd.read_csv("data/attack.csv")
df.columns=df.columns.str.strip()
labels=df["Normal/Attack"]
df=df.drop(columns=["Timestamp","Normal/Attack","MV101","AIT201","MV201","P201","P202","P204","MV303"])
print(df.shape)

scalerData=scaler.transform(df)
x=createSeq(scalerData,windowSize)
xTensor=torch.tensor(x,dtype=torch.float32)

with torch.no_grad():
    recon=model(xTensor)
    errors=torch.mean((recon-xTensor)**2,dim=(1,2))
    anomalies=torch.where(errors>threshold)[0]
    print("Detected Anomalies: ",len(anomalies))
    print("First anomalies: ", anomalies[:20])