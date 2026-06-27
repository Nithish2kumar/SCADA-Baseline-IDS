import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import numpy as np

#Fetch data
df = pd.read_csv("data/sensor_data.csv")
df = df.drop("timestamp", axis=1)

#Normalizing
scaler = MinMaxScaler()
scaled_data = scaler.fit_transform(df)

#Sampling the data
windowSize=10
def createSeq(data,window):
    sequences=[]
    for i in range(len(data)-window):
        sequences.append(data[i:i+window])
    
    return np.array(sequences)

x=createSeq(scaled_data,windowSize)
print(type(x))
print(x.shape)
#LSTM
