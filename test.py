# Poți rula asta și îmi spui rezultatul?
import joblib
model = joblib.load('RandomForest/RandomForest.joblib')
print(f"Model type: {type(model)}")
if hasattr(model, 'classes_'):
    print(f"Classes: {model.classes_}")  # [0, 1] sau ['legitimate', 'phishing']?