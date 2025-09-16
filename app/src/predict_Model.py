import joblib
import warnings
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
warnings.filterwarnings('ignore')

scaler = joblib.load(r"D:\Project_Exibition\Trace_hunter2\app\models\StandardScaler.pkl")
loaded_model = joblib.load(r"D:\Project_Exibition\Trace_hunter2\app\models\random_forest_model.pkl")

feature_names = [
    'pslist_nproc', 'pslist_nppid', 'pslist_avg_threads',
    'pslist_avg_handlers', 'dlllist_ndlls', 'dlllist_avg_dlls_per_proc',
    'handles_nhandles', 'handles_avg_handles_per_proc', 'handles_nfile',
    'handles_nevent', 'handles_ndesktop', 'handles_nkey', 'handles_nthread',
    'handles_ndirectory', 'handles_nsemaphore', 'handles_ntimer',
    'handles_nsection', 'handles_nmutant', 'ldrmodules_not_in_load',
    'ldrmodules_not_in_init', 'ldrmodules_not_in_mem',
    'ldrmodules_not_in_load_avg', 'ldrmodules_not_in_init_avg',
    'ldrmodules_not_in_mem_avg', 'malfind_ninjections',
    'malfind_commitCharge', 'malfind_protection', 'malfind_uniqueInjections',
    'psxview_not_in_pslist', 'psxview_not_in_eprocess_pool',
    'psxview_not_in_ethread_pool', 'psxview_not_in_pspcid_list',
    'psxview_not_in_csrss_handles', 'psxview_not_in_session',
    'psxview_not_in_deskthrd', 'psxview_not_in_eprocess_pool_false_avg',
    'psxview_not_in_ethread_pool_false_avg',
    'psxview_not_in_pspcid_list_false_avg',
    'psxview_not_in_csrss_handles_false_avg',
    'psxview_not_in_session_false_avg',
    'psxview_not_in_deskthrd_false_avg', 'modules_nmodules',
    'svcscan_nservices', 'svcscan_kernel_drivers', 'svcscan_fs_drivers',
    'svcscan_process_services', 'svcscan_shared_process_services',
    'svcscan_nactive', 'callbacks_ncallbacks'
]

simple_names = [
    "Total Processes", "Parent Process Count", "Avg Threads per Process",
    "Avg Handlers per Process", "Total DLLs Loaded", "Avg DLLs per Process",
    "Total System Handles", "Avg Handles per Process", "File Handles",
    "Event Handles", "Desktop Handles", "Registry Key Handles", "Thread Handles",
    "Directory Handles", "Semaphore Handles", "Timer Handles",
    "Section Handles", "Mutex (Mutant) Handles", "DLLs Not in Load List",
    "DLLs Not in Init List", "DLLs Not in Memory",
    "Avg DLLs Not in Load", "Avg DLLs Not in Init", "Avg DLLs Not in Memory",
    "Code Injections Found", "Memory Used by Injections", "Memory Protection Type",
    "Unique Code Injections", "Processes Hidden from Task Manager",
    "Hidden from EPROCESS Pool", "Hidden from ETHREAD Pool",
    "Hidden from PSPCID List", "Hidden from CSRSS", "Hidden from Session",
    "Hidden from Desktop Threads", "False Negatives in EPROCESS",
    "False Negatives in ETHREAD", "False Negatives in PSPCID",
    "False Negatives in CSRSS", "False Negatives in Session",
    "False Negatives in Desktop Threads", "Total Modules Loaded",
    "Total Services", "Kernel-Level Drivers", "File System Drivers",
    "Services Linked to Processes", "Shared Process Services",
    "Active Services", "System Callback Count"
]


# X = [[
#     85,      # pslist_nproc (high number of processes)
#     80,      # pslist_nppid
#     18.7,    # pslist_avg_threads (elevated)
#     600.3,   # pslist_avg_handlers (very high)
#     250,     # dlllist_ndlls
#     4.2,     # dlllist_avg_dlls_per_proc
#     50000,   # handles_nhandles (abnormal handle count)
#     588.2,   # handles_avg_handles_per_proc
#     420,     # handles_nfile
#     90,      # handles_nevent
#     15,      # handles_ndesktop
#     60,      # handles_nkey
#     40,      # handles_nthread
#     35,      # handles_ndirectory
#     25,      # handles_nsemaphore
#     22,      # handles_ntimer
#     33,      # handles_nsection
#     20,      # handles_nmutant
#     10,      # ldrmodules_not_in_load
#     9,       # ldrmodules_not_in_init
#     11,      # ldrmodules_not_in_mem
#     0.15,    # ldrmodules_not_in_load_avg
#     0.12,    # ldrmodules_not_in_init_avg
#     0.17,    # ldrmodules_not_in_mem_avg
#     5,       # malfind_ninjections
#     40000,   # malfind_commitCharge
#     5,       # malfind_protection
#     0.24,    # malfind_uniqueInjections
#     5,       # psxview_not_in_pslist
#     3,       # psxview_not_in_eprocess_pool
#     4,       # psxview_not_in_ethread_pool
#     6,       # psxview_not_in_pspcid_list
#     3,       # psxview_not_in_csrss_handles
#     2,       # psxview_not_in_session
#     3,       # psxview_not_in_deskthrd
#     0.03,    # psxview_not_in_eprocess_pool_false_avg
#     0.06,    # psxview_not_in_ethread_pool_false_avg
#     0.05,    # psxview_not_in_pspcid_list_false_avg
#     0.02,    # psxview_not_in_csrss_handles_false_avg
#     0.01,    # psxview_not_in_session_false_avg
#     0.04,    # psxview_not_in_deskthrd_false_avg
#     55,      # modules_nmodules (high number of modules)
#     230,     # svcscan_nservices
#     15,      # svcscan_kernel_drivers
#     11,      # svcscan_fs_drivers
#     35,      # svcscan_process_services
#     0,       # svcscan_shared_process_services
#     55,      # svcscan_nactive
#     19,      # callbacks_ncallbacks
# ]]



def load_and_clean_csv(df):
    drop_cols = [
        'pslist_nprocs64bit',
        'handles_nport',
        'psxview_not_in_pslist_false_avg',
        'svcscan_interactive_process_services',
        'callbacks_ngeneric',
        'callbacks_nanonymous',
        'Raw_Type',
        'SubType',
        'Label'
    ]
    df = df.drop(columns=[col for col in drop_cols if col in df.columns], errors="ignore")
    return df.values

def full_prediction(X):
    X_scaled = scaler.transform(X)
    output = loaded_model.predict(X_scaled)
    rf_probabilities = loaded_model.predict_proba(X_scaled)

    result = "Malicious" if output[0] == 1 else "Benign-Safe"
    # print(f"  Probability [Benign]: {rf_probabilities[0][0]:.4f}")
    # print(f"  Probability [Malicious]: {rf_probabilities[0][1]:.4f}")
    return (result, (rf_probabilities[0][0],rf_probabilities[0][1]))


def save_prediction_bar(probabilities, save_path="D:/Project_Exibition/Trace_hunter2/app/static/prediction_prob.png"):
    labels = ["Benign", "Malicious"]
    probs = [probabilities[0], probabilities[1]]
    
    plt.figure(figsize=(6, 5))
    sns.set_style("whitegrid")
    colors = sns.color_palette("Set2", 2)
    
    plt.bar(labels, probs, color=colors)
    plt.ylim(0, 1)  # probabilities range from 0 to 1
    plt.ylabel("Probability")
    plt.title("Prediction Probabilities")
    
    for i, v in enumerate(probs):
        plt.text(i, v + 0.02, f"{v:.2f}", ha="center", fontsize=12)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close()
    return save_path


def feature_importances(save_path="D:/Project_Exibition/Trace_hunter2/app/static/feature_importances.png"):
    importances = loaded_model.feature_importances_
    top_n = 20
    indices = np.argsort(importances)[::-1][:top_n]
    top_importances = importances[indices]
    top_features = [simple_names[i] for i in indices]

    plt.figure(figsize=(12, 8))
    sns.set_style("whitegrid")
    colors = sns.color_palette("viridis", top_n)

    bars = plt.barh(range(top_n), top_importances[::-1], color=colors[::-1])
    plt.yticks(range(top_n), top_features[::-1], fontsize=11)
    plt.xlabel("Feature Importance Score", fontsize=12)
    plt.title("Top 20 Most Important Features in Malware Detection", fontsize=14)
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close()
    return save_path
    
# path = r"D:\Project_Exibition\Trace_hunter2\data\new.xlsx"
# df = pd.read_excel(path)
# (m,p)=full_prediction(load_and_clean_csv(df))
# save_prediction_bar(p)
# feature_importances()














