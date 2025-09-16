# Ransomware Detection from Memory Dumps

This project builds a machine learning model to detect ransomware infections using memory forensic features.

## 📁 Structure
- `data/`: Input dataset CSV
- `models/`: Saved model, scaler, encoders
- `src/`: Training and prediction scripts
- `app/`: Streamlit UI
- `output/`: Evaluation results like feature plots

## 🚀 Usage
1. Install requirements:
```bash
pip install -r requirements.txt
```

2. Train the model:
```bash
python src/train_model.py
```

3. Predict a sample:
```bash
python src/predict_sample.py
```

4. Run Streamlit UI:
```bash
streamlit run app/streamlit_app.py
```

## 📊 Features Used
Includes system internals like process/thread counts, handles, psxview flags, dlls, etc.

## 📌 Dataset
Total: 58,596 records (29,298 benign, 29,298 malicious) with 58 behavioral features.

---

Let me know if you want Docker setup or cloud deployment next.


## === File: .gitignore ===

# Byte-compiled / cache
__pycache__/
*.py[cod]

# Model files
models/*.pkl

# Logs and outputs
output/*.png
output/*.log

# Env
.env
.venv/

# Streamlit
.streamlit/

# Jupyter
.ipynb_checkpoints/