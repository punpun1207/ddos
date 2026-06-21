# train_dnn_improved_v2.py
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, regularizers, callbacks

# ------------------------------
# 1. Đọc dữ liệu
# ------------------------------
df = pd.read_csv('ddos_multi.csv')
print("Shape:", df.shape)
print("Label distribution:\n", df['label'].value_counts().sort_index())

feature_cols = ['SYN_ratio', 'ACK_ratio', 'UDP_ratio', 'ICMP_ratio',
                'Pkt_rate', 'Byte_rate', 'entropy_src', 'entropy_dst']
X = df[feature_cols].copy()
y = df['label'].copy()
X = X.replace(-0.0, 0.0)

# ------------------------------
# 2. Chuẩn hóa
# ------------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ------------------------------
# 3. Chia train/test
# ------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# ------------------------------
# 4. SMOTE (có thể tắt)
# ------------------------------
use_smote = True
if use_smote:
    smote = SMOTE(random_state=42)
    X_train, y_train = smote.fit_resample(X_train, y_train)
    print("After SMOTE:", pd.Series(y_train).value_counts().sort_index())

# ------------------------------
# 5. One-hot & class weights
# ------------------------------
num_classes = 5
y_train_cat = keras.utils.to_categorical(y_train, num_classes)
y_test_cat = keras.utils.to_categorical(y_test, num_classes)

from sklearn.utils.class_weight import compute_class_weight
class_weights = compute_class_weight('balanced', classes=np.unique(y), y=y)
class_weight_dict = dict(zip(np.unique(y), class_weights))
print("Class weights:", class_weight_dict)

# ------------------------------
# 6. Mô hình DNN cải tiến
# ------------------------------
model = keras.Sequential([
    layers.Input(shape=(X_train.shape[1],)),
    layers.Dense(512, kernel_regularizer=regularizers.l2(1e-5)),
    layers.BatchNormalization(),
    layers.LeakyReLU(alpha=0.1),
    layers.Dropout(0.2),

    layers.Dense(256, kernel_regularizer=regularizers.l2(1e-5)),
    layers.BatchNormalization(),
    layers.LeakyReLU(alpha=0.1),
    layers.Dropout(0.2),

    layers.Dense(128, kernel_regularizer=regularizers.l2(1e-5)),
    layers.BatchNormalization(),
    layers.LeakyReLU(alpha=0.1),
    layers.Dropout(0.2),

    layers.Dense(64, kernel_regularizer=regularizers.l2(1e-5)),
    layers.BatchNormalization(),
    layers.LeakyReLU(alpha=0.1),
    layers.Dropout(0.2),

    layers.Dense(num_classes, activation='softmax')
])

model.compile(optimizer=keras.optimizers.Adam(learning_rate=0.0005),
              loss='categorical_crossentropy',
              metrics=['accuracy'])
model.summary()

# ------------------------------
# 7. Callbacks (patience=15)
# ------------------------------
early_stop = callbacks.EarlyStopping(monitor='val_loss', patience=15, restore_best_weights=True)
reduce_lr = callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=7, min_lr=1e-7)

# ------------------------------
# 8. Huấn luyện (batch_size=128)
# ------------------------------
history = model.fit(
    X_train, y_train_cat,
    validation_split=0.2,
    epochs=200,
    batch_size=128,
    callbacks=[early_stop, reduce_lr],
    class_weight=class_weight_dict,
    verbose=1
)

# ------------------------------
# 9. Đánh giá
# ------------------------------
y_pred_prob = model.predict(X_test)
y_pred = np.argmax(y_pred_prob, axis=1)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, digits=4))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# ------------------------------
# 10. Lưu model & scaler
# ------------------------------
model.save('ddos_dnn.h5')
joblib.dump(scaler, 'scaler_dnn.pkl')
print("Saved: ddos_dnn_improved_v2.h5 and scaler_dnn_improved_v2.pkl")