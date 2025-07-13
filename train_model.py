# train_model.py
import joblib
from sklearn.linear_model import LogisticRegression

# Sample synthetic data: [length, charset_size, entropy], label (1 = strong, 0 = weak)
X = [
    [5, 26, 23.5],   # omkar
    [8, 62, 48.5],   # Omkar@12
    [10, 72, 59.5],  # 0Mk@r123!
    [12, 85, 71.2],  # Good$Password9
    [4, 10, 13.3],   # 1234
    [6, 36, 32.2],   # Qwerty
    [14, 90, 79.1],  # S3cuRe!P@55w0rd
]

y = [0, 1, 1, 1, 0, 0, 1]  # labels for above data

model = LogisticRegression()
model.fit(X, y)

joblib.dump(model, "model.pkl")
print("[+] model.pkl saved successfully.")
