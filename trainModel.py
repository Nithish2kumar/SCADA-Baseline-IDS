#Fetch data
import pandas as pd
df=pd.read_csv("data/normal.csv")
df.columns=df.columns.str.strip()

# Remove unwanted columns
df=df.drop(columns=["Timestamp","Normal/Attack","MV101","AIT201","MV201","P201","P202","P204","MV303"])
df=df.iloc[:100000]
print(df.shape)

#Normalizing
from sklearn.preprocessing import MinMaxScaler
scaler=MinMaxScaler()
scaled_data=scaler.fit_transform(df)

#Sampling the data
import numpy as np
windowSize=20
def createSeq(data,window):
    sequences=[]
    for i in range(len(data)-window):
        sequences.append(data[i:i+window])
    
    return np.array(sequences)

x=createSeq(scaled_data,windowSize)
print(x.shape)

#LSTM
import torch
import torch.nn as nn
xTensor=torch.tensor(x,dtype=torch.float32)
print(xTensor.shape)

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
    
model=TestModel()
criterion=nn.MSELoss()
optimizer=torch.optim.Adam(model.parameters(),lr=0.001)
#Training the model (Adjusting the weight to get closest input value)
epochs=50
for epoch in range(epochs):
    optimizer.zero_grad()
    recon=model(xTensor)
    loss=criterion(recon,xTensor)
    loss.backward()
    optimizer.step()
    print(f"Epoch {epoch+1}: {loss.item():.6f}")

#Calculating error
recon=model(xTensor)
errors=torch.mean((recon-xTensor)**2, dim=(1,2))
meanError=errors.mean()
stdError=errors.std()
threshold=meanError+3*stdError
print("Mean error: ",meanError.item())
print("Std error: ",stdError.item())
print("Threshold: ",threshold.item())

#Finding anomalies
anomalies=torch.where(errors>threshold)[0]
print("No.of anomalies: ",len(anomalies))
print("First anomalies: ",anomalies[:20])

#save model,threshold and scalar
torch.save(model.state_dict(),"model.pth")
torch.save(threshold, "threshold.pth")
import joblib
joblib.dump(scaler,"scaler.pkl")
