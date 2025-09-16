import psutil
import wmi
import pandas as pd

def safe_get(info, key):
    value = info.get(key)
    return value if isinstance(value, (int, float)) else 0

def collect_features():
    features = {}

    # ------------------ psutil: process list ------------------
    processes = list(psutil.process_iter(['pid', 'ppid', 'num_threads', 'num_handles']))
    nprocs = len(processes)
    features['pslist_nproc'] = nprocs
    features['pslist_nppid'] = len(set(p.info['ppid'] for p in processes if p.info['ppid'] is not None))

    threads = [safe_get(p.info, 'num_threads') for p in processes]
    handles = [safe_get(p.info, 'num_handles') for p in processes]

    features['pslist_avg_threads'] = sum(threads) / nprocs if nprocs else 0
    features['pslist_avg_handlers'] = sum(handles) / nprocs if nprocs else 0

    # ------------------ DLL List (Approximated) ------------------
    features['dlllist_ndlls'] = 0
    features['dlllist_avg_dlls_per_proc'] = 0.0

    # ------------------ Handles ------------------
    features['handles_nhandles'] = sum(handles)
    features['handles_avg_handles_per_proc'] = features['handles_nhandles'] / nprocs if nprocs else 0

    features['handles_nfile'] = 0
    features['handles_nevent'] = 0
    features['handles_ndesktop'] = 0
    features['handles_nkey'] = 0
    features['handles_nthread'] = 0
    features['handles_ndirectory'] = 0
    features['handles_nsemaphore'] = 0
    features['handles_ntimer'] = 0
    features['handles_nsection'] = 0
    features['handles_nmutant'] = 0

    # ------------------ Ldrmodules ------------------
    features['ldrmodules_not_in_load'] = 0
    features['ldrmodules_not_in_init'] = 0
    features['ldrmodules_not_in_mem'] = 0
    features['ldrmodules_not_in_load_avg'] = 0.0
    features['ldrmodules_not_in_init_avg'] = 0.0
    features['ldrmodules_not_in_mem_avg'] = 0.0

    # ------------------ Malfind ------------------
    features['malfind_ninjections'] = 0
    features['malfind_commitCharge'] = 0
    features['malfind_protection'] = 0
    features['malfind_uniqueInjections'] = 0.0

    # ------------------ Psxview ------------------
    features['psxview_not_in_pslist'] = 0
    features['psxview_not_in_eprocess_pool'] = 0
    features['psxview_not_in_ethread_pool'] = 0
    features['psxview_not_in_pspcid_list'] = 0
    features['psxview_not_in_csrss_handles'] = 0
    features['psxview_not_in_session'] = 0
    features['psxview_not_in_deskthrd'] = 0

    features['psxview_not_in_eprocess_pool_false_avg'] = 0.0
    features['psxview_not_in_ethread_pool_false_avg'] = 0.0
    features['psxview_not_in_pspcid_list_false_avg'] = 0.0
    features['psxview_not_in_csrss_handles_false_avg'] = 0.0
    features['psxview_not_in_session_false_avg'] = 0.0
    features['psxview_not_in_deskthrd_false_avg'] = 0.0

    # ------------------ Modules ------------------
    features['modules_nmodules'] = 0

    # ------------------ Services using WMI ------------------
    c = wmi.WMI()
    services = c.Win32_Service()
    features['svcscan_nservices'] = len(services)
    features['svcscan_kernel_drivers'] = len([s for s in services if "kernel" in (s.PathName or "").lower()])
    features['svcscan_fs_drivers'] = len([s for s in services if "fs" in (s.PathName or "").lower()])
    features['svcscan_process_services'] = len([s for s in services if "svchost" in (s.PathName or "").lower()])
    features['svcscan_shared_process_services'] = 0
    features['svcscan_nactive'] = len([s for s in services if s.State == "Running"])

    # ------------------ Callbacks ------------------
    features['callbacks_ncallbacks'] = 0


    return features

if __name__ == "__main__":
    features = collect_features()
    df = pd.DataFrame([features])
    df.to_csv("data/live_features.csv", index=False)
    print("✅ Features collected and saved to 'live_features.csv'")
