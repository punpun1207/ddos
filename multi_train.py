import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, LeakyReLU, Input
from tensorflow.keras.regularizers import l2
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.utils import to_categorical
import joblib

df = pd.read_csv('ddos_multi.csv')
df = df[df['label'].isin([0,1,2,3,4])]
feature_cols = [c for c in df.columns if c != 'label']
X = df[feature_cols].values
y = df['label'].values.astype(int)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
y_cat = to_categorical(y, num_classes=5)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_cat, test_size=0.25, random_state=42, stratify=y)

model = Sequential([
    Input(shape=(X.shape[1],)),
    Dense(128, kernel_regularizer=l2(1e-4)), BatchNormalization(), LeakyReLU(), Dropout(0.2),
    Dense(64, kernel_regularizer=l2(1e-4)), BatchNormalization(), LeakyReLU(), Dropout(0.3),
    Dense(32, kernel_regularizer=l2(1e-4)), BatchNormalization(), LeakyReLU(), Dropout(0.3),
    Dense(5, activation='softmax')
])

model.compile(optimizer=Adam(1e-3), loss='categorical_crossentropy', metrics=['accuracy'])
callbacks = [EarlyStopping(patience=10, restore_best_weights=True),
             ReduceLROnPlateau(patience=5, factor=0.5)]

model.fit(X_train, y_train, epochs=100, batch_size=64, validation_split=0.2, callbacks=callbacks)

loss, acc = model.evaluate(X_test, y_test)
print(f"Test accuracy: {acc*100:.2f}%")

model.save('ddos_multi_model.h5')
joblib.dump(scaler, 'scaler_multi.pkl')
print("Saved model and scaler.")