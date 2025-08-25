# gui_mylobot_yara_advanced.py
# Author: Muhammad Askari | Telegram: https://t.me/moli1369
# Advanced Malware detection with heuristic + YARA rules, full system scan
# اهدا شده به اسکله رجایی و خلیج پژم

import os, ctypes, datetime, threading, shutil, tkinter as tk
from tkinter import ttk, messagebox
import yara
import win32api, win32file

APP_NAME = "MyloBot YARA Scanner & Cleaner (Advanced)"
AUTHOR_TEXT = "Muhammad Askari | Telegram: https://t.me/moli1369 | اهدایی به اسکله رجایی بندرعباس و شرکت  خلیج پژم"
RESULTS = []
STOP_REQUESTED = False
SCAN_THREAD = None
LOCK = threading.Lock()

SUSP_EXTS = (".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1")
RECENT_DAYS = 30
RULES_PATH = "rules"
QUARANTINE_PATH = "quarantine"

# ---------------- Helper Functions ----------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def set_status(label, text):
    label.config(text=text)
    label.update_idletasks()

def pulse(progress):
    try: progress.step(1)
    except Exception: pass

def add_finding(ftype, location, detail, extra=""):
    with LOCK:
        RESULTS.append({"Type": ftype, "Location": location, "Detail": detail, "Extra": extra, "Selected": tk.BooleanVar(value=True)})

# ---------------- YARA Handling ----------------
def load_yara_rules():
    rules_list = []
    if not os.path.exists(RULES_PATH):
        os.makedirs(RULES_PATH)
    for f in os.listdir(RULES_PATH):
        if f.lower().endswith(".yar"):
            try:
                rules_list.append(yara.compile(os.path.join(RULES_PATH, f)))
            except Exception as e:
                print("[YARA compile error]", f, e)
    return rules_list

def scan_with_yara(filepath, yara_rules):
    matches = []
    if not yara_rules: return matches
    try:
        for r in yara_rules:
            m = r.match(filepath)
            if m:
                matches.extend(m)
    except Exception:
        pass
    return matches

# ---------------- Filesystem Scan ----------------
def get_all_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            letter = f"{chr(65+i)}:\\"
            drives.append(letter)
    return drives

def scan_filesystem(update_status, progress, yara_rules, full_scan=False):
    cutoff = datetime.datetime.now() - datetime.timedelta(days=RECENT_DAYS)
    drives = get_all_drives()
    for root_drive in drives:
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root_drive)
        # Skip non-fixed drives if full_scan=False
        if not full_scan and drive_type != 3:  # DRIVE_FIXED
            continue
        for root, dirs, files in os.walk(root_drive):
            if STOP_REQUESTED: return
            update_status(f"Scanning: {root}")
            for fname in files:
                if STOP_REQUESTED: return
                fpath = os.path.join(root, fname)
                low = fname.lower()
                if full_scan or low.endswith(SUSP_EXTS):
                    try:
                        st = os.stat(fpath)
                        mtime = datetime.datetime.fromtimestamp(st.st_mtime)
                        recent = mtime >= cutoff
                        flagged = recent or ("programdata" in fpath.lower() or "appdata" in fpath.lower() or "\\temp\\" in fpath.lower())
                        yara_matches = scan_with_yara(fpath, yara_rules)
                        if flagged or yara_matches:
                            extra = "recent/heuristic"
                            if yara_matches:
                                extra += f" | YARA: {[x.rule for x in yara_matches]}"
                            add_finding("File", fpath, f"Modified: {mtime:%Y-%m-%d %H:%M:%S}", extra)
                    except Exception: continue
            pulse(progress)

# ---------------- Quarantine / Delete / Restore ----------------
def is_system_file(filepath):
    sys_paths = [os.environ.get("SystemRoot", "C:\\Windows"), os.environ.get("ProgramFiles", "C:\\Program Files")]
    return any(filepath.lower().startswith(p.lower()) for p in sys_paths)

def quarantine_files(selected_items):
    if not os.path.exists(QUARANTINE_PATH):
        os.makedirs(QUARANTINE_PATH)
    for item in selected_items:
        path = item["Location"]
        if is_system_file(path):
            messagebox.showwarning("System File", f"فایل سیستمی است و نمی‌توان آن را پاک یا قرنطینه کرد:\n{path}")
            continue
        try:
            shutil.move(path, os.path.join(QUARANTINE_PATH, os.path.basename(path)))
        except Exception as e:
            messagebox.showerror("Error", f"خطا در قرنطینه فایل:\n{path}\n{e}")

def delete_files(selected_items):
    for item in selected_items:
        path = item["Location"]
        if is_system_file(path):
            messagebox.showwarning("System File", f"فایل سیستمی است و نمی‌توان آن را حذف کرد:\n{path}")
            continue
        try:
            os.remove(path)
        except Exception as e:
            messagebox.showerror("Error", f"خطا در حذف فایل:\n{path}\n{e}")

def restore_files(selected_items):
    for item in selected_items:
        name = os.path.basename(item["Location"])
        restore_path = os.path.join(os.getcwd(), name)
        quarantine_file = os.path.join(QUARANTINE_PATH, name)
        if not os.path.exists(quarantine_file):
            continue
        try:
            shutil.move(quarantine_file, restore_path)
        except Exception as e:
            messagebox.showerror("Error", f"خطا در بازگردانی فایل:\n{name}\n{e}")

# ---------------- GUI ----------------
def build_gui():
    global STOP_REQUESTED, SCAN_THREAD
    root = tk.Tk()
    root.title(APP_NAME)
    root.geometry("1300x750")

    top = ttk.Frame(root); top.pack(fill="x", padx=10, pady=8)
    status = ttk.Label(top, text="برای شروع اسکن، نوع اسکن را انتخاب و روی 'شروع اسکن' کلیک کنید."); status.pack(fill="x")
    progress = ttk.Progressbar(top, mode="determinate"); progress.pack(fill="x", pady=4)
    btns = ttk.Frame(root); btns.pack(fill="x")

    scan_type_var = tk.StringVar(value="quick")
    ttk.Radiobutton(btns, text="اسکن سریع", variable=scan_type_var, value="quick").pack(side="left", padx=5)
    ttk.Radiobutton(btns, text="اسکن کامل", variable=scan_type_var, value="full").pack(side="left", padx=5)

    cols = ("Sel", "Type", "Location", "Detail", "Extra")
    tree = ttk.Treeview(root, columns=cols, show="headings", height=20)
    for c, w in zip(cols, (55, 120, 520, 220, 120)):
        tree.heading(c, text=c); tree.column(c, width=w, anchor="w")
    tree.pack(fill="both", expand=True, padx=10, pady=6)

    # ---------------- Buttons ----------------
    def run_scan_thread():
        global STOP_REQUESTED, SCAN_THREAD
        if SCAN_THREAD and SCAN_THREAD.is_alive():
            messagebox.showinfo("Scan", "اسکن در حال اجراست!")
            return
        STOP_REQUESTED = False
        with LOCK: RESULTS.clear()
        for row in tree.get_children(): tree.delete(row)
        progress.config(mode="indeterminate"); progress.start(8)
        yara_rules = load_yara_rules()
        full_scan = scan_type_var.get() == "full"
        def job():
            try:
                scan_filesystem(lambda msg: set_status(status,msg), progress, yara_rules, full_scan=full_scan)
            finally:
                progress.stop(); progress.config(mode="determinate", value=0)
                with LOCK: items = list(RESULTS)
                for r in items:
                    tree.insert("", "end", values=(
                        "✔" if r["Selected"].get() else "",
                        r["Type"], r["Location"], r["Detail"], r["Extra"]
                    ))
                set_status(status, f"اسکن کامل شد ✅ — {len(items)} مورد مشکوک" if items else "هیچ مورد مشکوکی پیدا نشد ✅")
        SCAN_THREAD = threading.Thread(target=job, daemon=True)
        SCAN_THREAD.start()

    def on_stop(): 
        global STOP_REQUESTED; STOP_REQUESTED = True; set_status(status,"توقف درخواست شد...")

    def get_selected_items():
        selected = []
        for i in tree.selection():
            vals = tree.item(i, "values")
            for r in RESULTS:
                if r["Location"] == vals[2]:
                    selected.append(r)
        return selected

    def on_quarantine():
        items = get_selected_items()
        if not items: return
        quarantine_files(items)
        messagebox.showinfo("Quarantine", "عملیات قرنطینه انجام شد.")
        run_scan_thread()  # Refresh list

    def on_delete():
        items = get_selected_items()
        if not items: return
        delete_files(items)
        messagebox.showinfo("Delete", "عملیات حذف انجام شد.")
        run_scan_thread()  # Refresh list

    def on_restore():
        if not os.path.exists(QUARANTINE_PATH):
            messagebox.showinfo("Restore", "هیچ فایلی در quarantine موجود نیست.")
            return
        files = os.listdir(QUARANTINE_PATH)
        if not files:
            messagebox.showinfo("Restore", "هیچ فایلی در quarantine موجود نیست.")
            return
        selected = []
        for f in files:
            path = os.path.join(QUARANTINE_PATH, f)
            selected.append({"Location": path})
        restore_files(selected)
        messagebox.showinfo("Restore", "عملیات بازگردانی انجام شد.")

    def select_all():
        for item in tree.get_children():
            tree.selection_add(item)

    def deselect_all():
        for item in tree.selection():
            tree.selection_remove(item)

    ttk.Button(btns, text="🔍 شروع اسکن", command=run_scan_thread).pack(side="left", padx=5, pady=4)
    ttk.Button(btns, text="⏹️ توقف اسکن", command=on_stop).pack(side="left", padx=5, pady=4)
    ttk.Button(btns, text="🛡️ قرنطینه فایل‌های انتخاب شده", command=on_quarantine).pack(side="left", padx=5, pady=4)
    ttk.Button(btns, text="❌ حذف فایل‌های انتخاب شده", command=on_delete).pack(side="left", padx=5, pady=4)
    ttk.Button(btns, text="♻️ بازگردانی فایل‌های quarantine", command=on_restore).pack(side="left", padx=5, pady=4)
    ttk.Button(btns, text="✅ انتخاب همه", command=select_all).pack(side="left", padx=5, pady=4)
    ttk.Button(btns, text="☑️ عدم انتخاب همه", command=deselect_all).pack(side="left", padx=5, pady=4)

    # Footer
    footer = ttk.Label(root, text=AUTHOR_TEXT, anchor="center"); footer.pack(side="bottom", fill="x", padx=10, pady=6)

    if not is_admin():
        messagebox.showwarning("Admin", "برای بهترین نتیجه، برنامه را با Run as Administrator اجرا کنید.")
    return root

if __name__ == "__main__":
    app = build_gui()
    app.mainloop()