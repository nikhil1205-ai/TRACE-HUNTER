import numpy as np
import pandas as pd
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
import joblib
warnings.filterwarnings('ignore')


# model = joblib.load(r'D:\Project_Exibition\Trace_hunter2\app\models\random_forest_Network_model.pkl')
# expected_columns = joblib.load(r'D:\Project_Exibition\Trace_hunter2\app\models\model_columns_network.pkl')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # current file directory
MODEL_PATH = os.path.join(BASE_DIR, "..", "models", "random_forest_Network_model.pkl")
Ext_Path = os.path.join(BASE_DIR, "..", "models", "model_columns_network.pkl")
model = joblib.load(MODEL_PATH)
expected_columns = joblib.load(Ext_Path)

# Map labels
label_map = {0: "Benign-Safe", 1: "Attack Detected "}

def predict_attack(input_series: pd.Series):
    input_df = input_series.to_frame().T
    if 'session_id' in input_df.columns:
        input_df.drop('session_id', axis=1, inplace=True)
    if 'attack_detected' in input_df.columns:
        input_df.drop('attack_detected', axis=1, inplace=True)
    categorical_cols = ['protocol_type', 'encryption_used', 'browser_type']
    input_df = pd.get_dummies(input_df, columns=categorical_cols, drop_first=True)
    input_df = input_df.reindex(columns=expected_columns, fill_value=0)
    
    prediction = model.predict(input_df)[0]
    probas = model.predict_proba(input_df)[0]   # get probabilities
    
    readable_prediction = label_map.get(prediction, prediction)
    return readable_prediction, probas

def visualize_results(prediction, probas, expected_columns=expected_columns, model=model,
                      prob_path="D:/Project_Exibition/Trace_hunter2/app/static/prediction_Network_probability.png", fi_path="D:/Project_Exibition/Trace_hunter2/app/static/feature_Network_importances.png"):

    # ====== 1. Probability Distribution Plot ======
    class_labels = [label_map.get(c, str(c)) for c in model.classes_]

    plt.figure(figsize=(6,4))
    sns.barplot(x=class_labels, y=probas, palette="cool")
    plt.title("Prediction Probability Distribution")
    plt.xlabel("Classes")
    plt.ylabel("Probability")
    plt.tight_layout()
    plt.savefig(prob_path, dpi=300)
    plt.close()

    # ====== 2. Feature Importance Plot ======
    importances = model.feature_importances_
    features = expected_columns

    fi_df = pd.DataFrame({"Feature": features, "Importance": importances})
    fi_df = fi_df.sort_values(by="Importance", ascending=False).head(15)  # Top 15

    plt.figure(figsize=(8,6))
    sns.barplot(x="Importance", y="Feature", data=fi_df, palette="viridis")
    plt.title("Top Feature Importances")
    plt.tight_layout()
    plt.savefig(fi_path, dpi=300)
    plt.close()


# df = pd.read_csv(r'data\cybersecurity_intrusion_data.csv')
# prediction, probas = predict_attack(df.iloc[0,:-1])
# visualize_results(prediction, probas, expected_columns, model)








