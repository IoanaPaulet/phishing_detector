# 🧠 Random Forest Model Setup

## ⚠️ Model File Not Included
The trained Random Forest model (\RandomForest.joblib\ - 427MB) is excluded due to GitHub size limits.

## 🚀 How to Setup

### Method 1: Use Jupyter Notebook (Recommended)
\\\ash
pip install -r requirements.txt
jupyter notebook main.ipynb
# Run all cells to train and save the model
\\\

### Method 2: Quick Basic Model for Testing
\\\python
# create_model.py
import joblib
from sklearn.ensemble import RandomForestClassifier
import os

os.makedirs('RandomForest', exist_ok=True)
model = RandomForestClassifier(n_estimators=100, random_state=42)
X = [[1, 0, 1], [0, 1, 0], [1, 1, 1], [0, 0, 0]]
y = [1, 0, 1, 0]
model.fit(X, y)
joblib.dump(model, 'RandomForest/RandomForest.joblib')
print("✅ Model created!")
\\\

## 📁 Expected Result
After training: \RandomForest/RandomForest.joblib\

The extension will automatically detect and load this model.

## 🔧 Troubleshooting
- Make sure all requirements are installed
- Check that the model file exists after training
- Restart the browser extension after model creation
