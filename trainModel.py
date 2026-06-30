#Fetch data
import pandas as pd
df=pd.read_csv("data/sensor_data.csv")
df=df.drop("timestamp", axis=1)

#Normalizing
from sklearn.preprocessing import MinMaxScaler
scaler=MinMaxScaler()
scaled_data=scaler.fit_transform(df)

#Sampling the data
import numpy as np
windowSize=10
def createSeq(data,window):
    sequences=[]
    for i in range(len(data)-window):
        sequences.append(data[i:i+window])
    
    return np.array(sequences)

x=createSeq(scaled_data,windowSize)

#LSTM
import torch
import torch.nn as nn
xTensor=torch.tensor(x,dtype=torch.float32)

class TestModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder=nn.LSTM(input_size=6,hidden_size=64,batch_first=True)
        self.decoder=nn.LSTM(input_size=64,hidden_size=64,batch_first=True)
        self.output_layer=nn.Linear(64,6)
    def forward(self, x):
        _,(hidden,cell)=self.encoder(x)
        hidden=hidden.squeeze(0)
        decoderInput=hidden.unsqueeze(1)
        decoderInput=decoderInput.repeat(1,10,1)
        decoderOutput,_=self.decoder(decoderInput)
        reconstructed=self.output_layer(decoderOutput)
        return reconstructed
    
model=TestModel()
criterion=nn.MSELoss()
optimizer=torch.optim.Adam(model.parameters(),lr=0.001)
recon=model(xTensor)
loss=criterion(recon,xTensor)
print(loss)
print(recon.shape)