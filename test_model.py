import joblib
import os

print(f"Current directory: {os.getcwd()}")
print(f"Files in RandomForest/: {os.listdir('RandomForest') if os.path.exists('RandomForest') else 'Folder not found'}")

model = joblib.load('RandomForest/RandomForest.joblib')
print(f"Model type: {type(model)}")
print(f"Model: {model}")