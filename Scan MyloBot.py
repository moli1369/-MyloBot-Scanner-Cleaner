# gui_mylobot_scanner_cleaner.py
# Author (Program by): Muhammad Askari | Telegram: https://t.me/moli1369
# Built with ❤️ for defensive use only.
# -------------------------------------------------------------
# What this app does
# - GUI (Tkinter) full-system scan for common malware persistence (Run/RunOnce, services, scheduled tasks)
# - Deep file scan across ALL FIXED DRIVES (C:, D:, ...) with live "currently scanning" path label
# - Heuristics for suspicious items (executables/scripts in ProgramData/AppData/Temp or recent writes)
# - Shows results in a table; lets user QUARANTINE (move) or PERMANENTLY DELETE selected items
# - Can stop/cancel an on-going scan
# - Displays author credit in the app footer (as requested)
#
# Requirements (Windows only):
#   pip install psutil pywin32
# Run as Administrator for full access!

import os
import sys
import time
import csv
import psutil
import winreg
import shutil
import ctypes
import datetime
import threading
import subprocess
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "MyloBot Scanner & Cleaner"
AUTHOR_TEXT = "Program by: Muhammad Askari | Telegram: https://t.me/moli1369"
RESULTS = []  # list of dicts
STOP_REQUESTED = False
SCAN_THREAD = None
LOCK = threading.Lock()

SUSP_EXTS = (".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1")
RECENT_DAYS = 30

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# --------------------------- GUI helpers ---------------------------

def set_status(label: tk.Label, text: str):
    label.config(text=text)
    label.update_idletasks()

def pulse(progress: ttk.Progressbar):
    try:
        progress.step(1)
    except Exception:
        pass

# ----------------------- Findings & Table --------------------------

def add_finding(ftype, location, detail, extra=""):
    with LOCK:
        RESULTS.append({
            "Type": ftype,
            "Location": location,
            "Detail": detail,
            "Extra": extra,
            "Selected": tk.BooleanVar(value=True),
        })

# ---------------------- Registry Scanning -------------------------

def scan_registry(update_status, progress):
    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ]
    for hive, key_path in run_keys:
        if STOP_REQUESTED: return
        try:
            update_status(f"در حال اسکن رجیستری: {key_path}")
            reg = winreg.OpenKey(hive, key_path)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(reg, i)
                    sval = str(val)
                    if ("ProgramData" in sval) or ("AppData" in sval) or sval.lower().endswith(SUSP_EXTS):
                        add_finding("Registry Run/RunOnce", f"{key_path}\\{name}", sval, "Startup reference")
                    i += 1
                except OSError:
                    break
        except OSError:
            pass
        pulse(progress)

# ---------------------- Services Scanning -------------------------

def scan_services(update_status, progress):
    update_status("در حال اسکن سرویس‌های ویندوز ...")
    for svc in psutil.win_service_iter():
        if STOP_REQUESTED: return
        try:
            info = svc.as_dict()
            path = info.get("binpath") or ""
            if any(x in path for x in ("ProgramData", "AppData")) or path.lower().endswith(SUSP_EXTS):
                add_finding("Service", info.get("name", ""), path, info.get("display_name", ""))
        except Exception:
            continue
    pulse(progress)

# ---------------------- Scheduled Tasks ---------------------------

def scan_schtasks(update_status, progress):
    update_status("در حال اسکن Scheduled Tasks ...")
    try:
        result = subprocess.run(["schtasks", "/query", "/fo", "LIST", "/v"], capture_output=True, text=True)
        task, exec_path = None, None
        for line in result.stdout.splitlines():
            if STOP_REQUESTED: return
            if line.startswith("TaskName:"):
                task = line.split(":",1)[1].strip()
            elif line.startswith("Task To Run:"):
                exec_path = line.split(":",1)[1].strip()
                if any(x in exec_path for x in ("ProgramData", "AppData")) or exec_path.lower().endswith(SUSP_EXTS):
                    add_finding("Scheduled Task", task or "(unknown)", exec_path, "Startup reference")
    except Exception:
        pass
    pulse(progress)

# ---------------------- Processes Scanning ------------------------

def scan_processes(update_status, progress):
    update_status("در حال بررسی پروسه‌های فعال ...")
    for p in psutil.process_iter(['pid','name','exe']):
        if STOP_REQUESTED: return
        exe = (p.info.get('exe') or "")
        if exe and ("ProgramData" in exe or "AppData" in exe):
            add_finding("Running Process", exe, f"PID: {p.info['pid']}", p.info['name'])
    pulse(progress)

# ---------------------- Filesystem Scan ---------------------------

def get_fixed_drives():
    # Use ctypes to filter only fixed drives
    drives = []
    DRIVE_FIXED = 3
    GetDriveType = ctypes.windll.kernel32.GetDriveTypeW
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            letter = f"{chr(65+i)}:\\"
            if GetDriveType(letter) == DRIVE_FIXED:
                drives.append(letter)
    return drives


def scan_filesystem(update_status, progress):
    cutoff = datetime.datetime.now() - datetime.timedelta(days=RECENT_DAYS)
    drives = get_fixed_drives()
    for root_drive in drives:
        for root, dirs, files in os.walk(root_drive):
            if STOP_REQUESTED: return
            # Show exactly where we are scanning
            update_status(f"در حال اسکن: {root}")
            for fname in files:
                if STOP_REQUESTED: return
                fpath = os.path.join(root, fname)
                low = fname.lower()
                if low.endswith(SUSP_EXTS):
                    try:
                        st = os.stat(fpath)
                        mtime = datetime.datetime.fromtimestamp(st.st_mtime)
                        recent = mtime >= cutoff
                        flagged = recent or ("programdata" in fpath.lower() or "appdata" in fpath.lower() or "\\temp\\" in fpath.lower())
                        if flagged:
                            add_finding("File", fpath, f"Modified: {mtime:%Y-%m-%d %H:%M:%S}", "recent/heuristic")
                    except Exception:
                        continue
        pulse(progress)

# ---------------------- Scan Orchestrator -------------------------

def run_full_scan(tree, progress, status_label, buttons_state):
    global STOP_REQUESTED
    STOP_REQUESTED = False
    with LOCK:
        RESULTS.clear()

    for row in tree.get_children():
        tree.delete(row)

    # Indeterminate progress since total work is unknown
    progress.config(mode="indeterminate")
    progress.start(8)

    def update_status(msg):
        set_status(status_label, msg)

    try:
        # Steps: registry, services, tasks, processes, filesystem
        scan_registry(update_status, progress)
        if STOP_REQUESTED: return
        scan_services(update_status, progress)
        if STOP_REQUESTED: return
        scan_schtasks(update_status, progress)
        if STOP_REQUESTED: return
        scan_processes(update_status, progress)
        if STOP_REQUESTED: return
        scan_filesystem(update_status, progress)
    finally:
        progress.stop()
        progress.config(mode="determinate", value=0)

    # Populate table
    with LOCK:
        items = list(RESULTS)

    if not items:
        messagebox.showinfo("نتیجه", "هیچ مورد مشکوکی پیدا نشد ✅")
        update_status("اسکن کامل شد ✅")
        return

    for r in items:
        tree.insert("", "end", values=("✔" if r["Selected"].get() else "", r["Type"], r["Location"], r["Detail"], r["Extra"]))

    update_status(f"اسکن کامل شد ✅ — {len(items)} مورد مشکوک")

# ---------------------- Actions (Quarantine/Delete) ---------------

def get_selected_from_table(tree):
    selected = []
    # Map back from table to RESULTS by Location+Type match
    with LOCK:
        items = list(RESULTS)
    table_items = tree.get_children()
    # If user wants, treat all rows as selected (since we pre-select True)
    for iid in table_items:
        vals = tree.item(iid, 'values')
        _chk, ftype, loc, detail, extra = vals
        for r in items:
            if r["Type"] == ftype and r["Location"] == loc and r["Detail"] == detail and r["Extra"] == extra:
                selected.append(r)
                break
    return selected


def ensure_quarantine_folder():
    qdir = Path(os.getenv("PROGRAMDATA", "C:/ProgramData")) / "MyloBotScanner_Quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    return qdir


def kill_process_using(path):
    for p in psutil.process_iter(['pid','name','exe']):
        try:
            if p.info.get('exe') and os.path.normcase(p.info['exe']) == os.path.normcase(path):
                p.kill()
        except Exception:
            continue


def quarantine_files(selected):
    qdir = ensure_quarantine_folder()
    moved = 0
    for r in selected:
        if r["Type"] != "File":
            continue
        src = r["Location"]
        try:
            if os.path.isfile(src):
                kill_process_using(src)
                base = os.path.basename(src)
                dst = qdir / f"{base}.{int(time.time())}.quar"
                shutil.move(src, dst)
                moved += 1
        except Exception as e:
            print("[quarantine error]", src, e)
    messagebox.showinfo("قرنطینه", f"{moved} فایل به قرنطینه منتقل شد.")


def delete_files_permanently(selected):
    removed = 0
    for r in selected:
        if r["Type"] != "File":
            continue
        path = r["Location"]
        try:
            if os.path.isfile(path):
                kill_process_using(path)
                os.remove(path)
                removed += 1
        except Exception as e:
            print("[delete error]", path, e)
    messagebox.showinfo("حذف", f"{removed} فایل حذف شد.")


def remove_registry_entries(selected):
    removed = 0
    for r in selected:
        if not r["Type"].lower().startswith("registry"):
            continue
        loc = r["Location"]  # e.g., keypath\\valueName
        try:
            keypath, valuename = loc.rsplit("\\", 1)
            # Try both HKLM and HKCU and WOW6432Node variants
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for base in (keypath,):
                    try:
                        with winreg.OpenKey(hive, base, 0, winreg.KEY_SET_VALUE) as k:
                            winreg.DeleteValue(k, valuename)
                            removed += 1
                            break
                    except Exception:
                        pass
        except Exception:
            continue
    messagebox.showinfo("Registry", f"{removed} مقدار رجیستری حذف شد.")


def remove_tasks(selected):
    removed = 0
    for r in selected:
        if r["Type"] != "Scheduled Task":
            continue
        tn = r["Location"]  # task name
        try:
            subprocess.run(["schtasks", "/Delete", "/TN", tn, "/F"], check=False, capture_output=True)
            removed += 1
        except Exception:
            pass
    messagebox.showinfo("Tasks", f"{removed} تسک زمان‌بندی‌شده حذف شد.")


def disable_services(selected):
    changed = 0
    for r in selected:
        if r["Type"] != "Service":
            continue
        svc = r["Location"]
        try:
            subprocess.run(["sc", "stop", svc], capture_output=True)
            subprocess.run(["sc", "config", svc, "start=", "disabled"], capture_output=True)
            changed += 1
        except Exception:
            pass
    messagebox.showinfo("Service", f"{changed} سرویس متوقف/غیرفعال شد.")

# ---------------------- GUI setup ---------------------------------

def build_gui():
    root = tk.Tk()
    root.title(APP_NAME)
    root.geometry("1100x650")

    # Top controls
    top = ttk.Frame(root)
    top.pack(fill="x", padx=10, pady=8)

    status = ttk.Label(top, text="برای شروع روی \"اسکن کامل سیستم\" کلیک کنید.")
    status.pack(fill="x", side="top")

    progress = ttk.Progressbar(top, mode="determinate")
    progress.pack(fill="x", pady=4)

    btns = ttk.Frame(top)
    btns.pack(fill="x")

    def on_scan():
        global SCAN_THREAD
        if SCAN_THREAD and SCAN_THREAD.is_alive():
            messagebox.showinfo("اسکن", "اسکن در حال اجراست.")
            return
        # Run scan in background
        def job():
            try:
                run_full_scan(tree, progress, status, btns)
            except Exception as e:
                messagebox.showerror("خطا", str(e))
        SCAN_THREAD = threading.Thread(target=job, daemon=True)
        SCAN_THREAD.start()

    def on_stop():
        global STOP_REQUESTED
        STOP_REQUESTED = True
        set_status(status, "درخواست توقف ثبت شد... لطفاً چند لحظه صبر کنید.")

    scan_btn = ttk.Button(btns, text="🔍 اسکن کامل سیستم", command=on_scan)
    scan_btn.pack(side="left", padx=5, pady=4)

    stop_btn = ttk.Button(btns, text="⏹️ توقف اسکن", command=on_stop)
    stop_btn.pack(side="left", padx=5, pady=4)

    save_btn = ttk.Button(btns, text="💾 ذخیره نتایج", command=lambda: save_results_dialog())
    save_btn.pack(side="left", padx=5, pady=4)

    # Results table
    cols = ("Sel", "Type", "Location", "Detail", "Extra")
    tree = ttk.Treeview(root, columns=cols, show="headings", height=20)
    for c, w in zip(cols, (55, 120, 520, 220, 120)):
        tree.heading(c, text=c)
        tree.column(c, width=w, anchor="w")
    tree.pack(fill="both", expand=True, padx=10, pady=6)

    # Action buttons (quarantine/delete/registry/task/service)
    actions = ttk.Frame(root)
    actions.pack(fill="x", padx=10, pady=6)

    ttk.Button(actions, text="🛡️ قرنطینه فایل‌های انتخاب‌شده",
               command=lambda: quarantine_files(get_selected_from_table(tree))).pack(side="left", padx=4)
    ttk.Button(actions, text="🗑️ حذف دائم فایل‌های انتخاب‌شده",
               command=lambda: (messagebox.askokcancel("تأیید حذف", "حذف دائمی انجام شود؟") and delete_files_permanently(get_selected_from_table(tree)))).pack(side="left", padx=4)
    ttk.Button(actions, text="🧹 حذف مقادیر رجیستری انتخاب‌شده",
               command=lambda: remove_registry_entries(get_selected_from_table(tree))).pack(side="left", padx=4)
    ttk.Button(actions, text="🧭 حذف Scheduled Tasks انتخاب‌شده",
               command=lambda: remove_tasks(get_selected_from_table(tree))).pack(side="left", padx=4)
    ttk.Button(actions, text="⛔ توقف و غیرفعال‌سازی سرویس‌های انتخاب‌شده",
               command=lambda: disable_services(get_selected_from_table(tree))).pack(side="left", padx=4)

    # Footer with author credit
    footer = ttk.Label(root, text=AUTHOR_TEXT, anchor="e")
    footer.pack(side="bottom", fill="x", padx=10, pady=6)

    # Export function inside to access RESULTS easily
    def save_results_dialog():
        with LOCK:
            items = list(RESULTS)
        if not items:
            messagebox.showinfo("ذخیره", "موردی برای ذخیره وجود ندارد.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files","*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Type","Location","Detail","Extra"])
            writer.writeheader()
            for r in items:
                writer.writerow({k: r[k] for k in ["Type","Location","Detail","Extra"]})
        messagebox.showinfo("ذخیره", f"فایل ذخیره شد:\n{path}")

    # Admin warning
    if not is_admin():
        messagebox.showwarning("دسترسی ادمین", "برای بهترین نتیجه، برنامه را با Run as Administrator اجرا کنید.")

    return root


if __name__ == "__main__":
    app = build_gui()
    app.mainloop()
