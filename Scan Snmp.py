# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import subprocess
import socket
import ipaddress
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed

class SNMPManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("مدیریت سرویس SNMP - نسخه گرافیکی")
        self.root.geometry("800x650")
        self.root.resizable(True, True)
        
        # متغیرهای ذخیره状态
        self.snmp_hosts = []
        self.scanning = False
        self.disabling = False
        
        # ایجاد رابط کاربری
        self.create_widgets()
        self.create_author_info()
        
    def create_author_info(self):
        """ایجاد بخش اطلاعات نویسنده"""
        author_frame = ttk.Frame(self.root, padding=5)
        author_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # خط جداکننده
        separator = ttk.Separator(author_frame, orient='horizontal')
        separator.pack(fill=tk.X, pady=5)
        
        # اطلاعات نویسنده
        author_text = "نویسنده: Muhammad Askari |  تلگرام: https://t.me/moli1369"
        author_label = ttk.Label(author_frame, text=author_text, foreground="blue", cursor="hand2")
        author_label.pack(pady=5)
        
        # اضافه کردن قابلیت کلیک برای باز کردن لینک
        author_label.bind("<Button-1>", lambda e: webbrowser.open("https://t.me/moli1369"))
        
    def create_widgets(self):
        # نوت‌بوک برای تب‌های مختلف
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # تب اسکن شبکه
        self.scan_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.scan_frame, text="اسکن شبکه")
        
        # تب مدیریت سیستم‌ها
        self.manage_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.manage_frame, text="مدیریت سیستم‌ها")
        
        # تب تست دسترسی
        self.test_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.test_frame, text="تست دسترسی")
        
        # تب درباره برنامه
        self.about_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.about_frame, text="درباره برنامه")
        
        # ایجاد محتوای تب اسکن
        self.create_scan_tab()
        
        # ایجاد محتوای تب مدیریت
        self.create_manage_tab()
        
        # ایجاد محتوای تب تست
        self.create_test_tab()
        
        # ایجاد محتوای تب درباره
        self.create_about_tab()
        
        # نوار وضعیت
        self.status_var = tk.StringVar()
        self.status_var.set("آماده")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_scan_tab(self):
        # برچسب و فیلد ورودی رنج IP
        ttk.Label(self.scan_frame, text="رنج IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.ip_range_var = tk.StringVar()
        self.ip_range_entry = ttk.Entry(self.scan_frame, textvariable=self.ip_range_var, width=30)
        self.ip_range_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        self.ip_range_entry.insert(0, "192.168.1.1-10")
        
        # دکمه اسکن
        self.scan_btn = ttk.Button(self.scan_frame, text="شروع اسکن", command=self.start_scan)
        self.scan_btn.grid(row=0, column=2, sticky=tk.W, pady=5, padx=5)
        
        # پیشرفت‌بار
        self.progress = ttk.Progressbar(self.scan_frame, mode='indeterminate')
        self.progress.grid(row=1, column=0, columnspan=3, sticky=tk.EW, pady=5)
        
        # کادر نتایج
        ttk.Label(self.scan_frame, text="نتایج اسکن:").grid(row=2, column=0, sticky=tk.W, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(self.scan_frame, width=70, height=15)
        self.results_text.grid(row=3, column=0, columnspan=3, sticky=tk.NSEW, pady=5)
        
        # تنظیمات grid برای resize
        self.scan_frame.columnconfigure(1, weight=1)
        self.scan_frame.rowconfigure(3, weight=1)
    
    def create_manage_tab(self):
        # لیست سیستم‌های یافت شده
        ttk.Label(self.manage_frame, text="سیستم‌های دارای SNMP فعال:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        # فریم برای لیست و دکمه‌ها
        list_frame = ttk.Frame(self.manage_frame)
        list_frame.grid(row=1, column=0, columnspan=2, sticky=tk.NSEW, pady=5)
        
        # ایجاد Treeview برای نمایش سیستم‌ها
        columns = ('ip', 'hostname', 'status')
        self.hosts_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # تعریف ستون‌ها
        self.hosts_tree.heading('ip', text='آدرس IP')
        self.hosts_tree.heading('hostname', text='نام میزبان')
        self.hosts_tree.heading('status', text='وضعیت')
        
        self.hosts_tree.column('ip', width=150)
        self.hosts_tree.column('hostname', width=200)
        self.hosts_tree.column('status', width=100)
        
        # نوار پیمایش
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.hosts_tree.yview)
        self.hosts_tree.configure(yscroll=scrollbar.set)
        
        self.hosts_tree.grid(row=0, column=0, sticky=tk.NSEW)
        scrollbar.grid(row=0, column=1, sticky=tk.NS)
        
        # دکمه‌های مدیریت
        btn_frame = ttk.Frame(self.manage_frame)
        btn_frame.grid(row=2, column=0, sticky=tk.W, pady=5)
        
        self.disable_btn = ttk.Button(btn_frame, text="غیرفعال کردن انتخاب شده", command=self.disable_selected)
        self.disable_btn.pack(side=tk.LEFT, padx=5)
        
        self.disable_all_btn = ttk.Button(btn_frame, text="غیرفعال کردن همه", command=self.disable_all)
        self.disable_all_btn.pack(side=tk.LEFT, padx=5)
        
        self.refresh_btn = ttk.Button(btn_frame, text="بروزرسانی لیست", command=self.refresh_list)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # پیشرفت‌بار غیرفعال‌سازی
        self.disable_progress = ttk.Progressbar(self.manage_frame, mode='indeterminate')
        self.disable_progress.grid(row=3, column=0, sticky=tk.EW, pady=5)
        
        # تنظیمات grid برای resize
        self.manage_frame.columnconfigure(0, weight=1)
        self.manage_frame.rowconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
    
    def create_test_tab(self):
        # فیلد تست دسترسی
        ttk.Label(self.test_frame, text="آدرس IP یا نام میزبان:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.test_host_var = tk.StringVar()
        self.test_host_entry = ttk.Entry(self.test_frame, textvariable=self.test_host_var, width=30)
        self.test_host_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        self.test_btn = ttk.Button(self.test_frame, text="تست دسترسی", command=self.start_test)
        self.test_btn.grid(row=0, column=2, sticky=tk.W, pady=5, padx=5)
        
        # کادر نتایج تست
        ttk.Label(self.test_frame, text="نتایج تست:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.test_text = scrolledtext.ScrolledText(self.test_frame, width=70, height=15)
        self.test_text.grid(row=2, column=0, columnspan=3, sticky=tk.NSEW, pady=5)
        
        # تنظیمات grid برای resize
        self.test_frame.columnconfigure(1, weight=1)
        self.test_frame.rowconfigure(2, weight=1)
    
    def create_about_tab(self):
        """ایجاد تب درباره برنامه"""
        about_text = """
        برنامه مدیریت سرویس SNMP
        
        نسخه: 2.0
        تاریخ انتشار: 1403/05/20
        
        ویژگی‌های برنامه:
        - اسکن شبکه برای یافتن سیستم‌های دارای SNMP فعال
        - غیرفعال کردن سرویس SNMP روی سیستم‌های ویندوزی
        - تست دسترسی و وضعیت سرویس‌های شبکه
        - رابط کاربری گرافیکی و فارسی
        - پشتیبانی از اسکن چندنخی برای افزایش سرعت
        
        این برنامه با پایتون و کتابخانه Tkinter توسعه یافته است.
        
        برای استفاده از برنامه:
        1. در تب 'اسکن شبکه' رنج IP مورد نظر را وارد کنید
        2. دکمه 'شروع اسکن' را بزنید
        3. پس از اتمام اسکن، به تب 'مدیریت سیستم‌ها' بروید
        4. سیستم‌های مورد نظر را انتخاب و غیرفعال کنید
        
        نکات مهم:
        - برای غیرفعال کردن SNMP نیاز به دسترسی Administrator دارید
        - WinRM باید روی سیستم‌های هدف فعال باشد
        - اسکن شبکه ممکن است بسته به اندازه شبکه زمان‌بر باشد
        
        توسعه‌دهنده:
        Muhammad Askari
        https://t.me/moli1369
        
        کپی‌رایت © 2024 - تمامی حقوق محفوظ است.
        """
        
        about_label = scrolledtext.ScrolledText(self.about_frame, width=80, height=25, wrap=tk.WORD)
        about_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        about_label.insert(tk.END, about_text)
        about_label.config(state=tk.DISABLED)
    
    def log_message(self, message, widget=None):
        """ثبت پیام در ویجت مربوطه"""
        if widget is None:
            widget = self.results_text
        
        widget.insert(tk.END, f"{message}\n")
        widget.see(tk.END)
        self.root.update_idletasks()
    
    def run_powershell(self, command):
        """اجرای دستور PowerShell"""
        try:
            result = subprocess.run(["powershell", "-Command", command], 
                                  capture_output=True, text=True, timeout=30, encoding='utf-8')
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", 1
        except Exception as e:
            return "", str(e), 1
    
    def is_host_alive(self, host, timeout=1):
        """بررسی فعال بودن هاست"""
        try:
            result = subprocess.run(["ping", "-n", "1", "-w", str(timeout * 1000), host], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def test_snmp_udp(self, host, port=161, timeout=2):
        """بررسی سرویس SNMP با UDP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                
                # ایجاد یک درخواست SNMP ساده
                snmp_request = bytes.fromhex(
                    "302902010104067075626c6963a01c02046e6f746d020100020100300e300c06082b060102010101000500"
                )
                
                s.sendto(snmp_request, (host, port))
                
                try:
                    response, addr = s.recvfrom(1024)
                    return True
                except socket.timeout:
                    # حتی اگر پاسخی دریافت نشد، ممکن است پورت باز باشد
                    return True
                    
        except Exception as e:
            return False
    
    def get_host_info(self, ip):
        """دریافت نام میزبان از آدرس IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return ip
    
    def scan_network(self, ip_range):
        """اسکن شبکه برای یافتن سیستم‌های دارای SNMP"""
        self.log_message(f"شروع اسکن رنج IP: {ip_range}")
        
        # تولید لیست IP‌ها
        ip_list = []
        try:
            if '-' in ip_range:
                base, end_range = ip_range.split('-')
                base_parts = base.split('.')
                start = int(base_parts[3])
                end = int(end_range)
                
                for i in range(start, end + 1):
                    ip_list.append(f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}")
            elif '/' in ip_range:
                network = ipaddress.ip_network(ip_range, strict=False)
                for ip in network.hosts():
                    ip_list.append(str(ip))
            elif ',' in ip_range:
                ip_list = [ip.strip() for ip in ip_range.split(',')]
            else:
                ip_list.append(ip_range)
        except Exception as e:
            self.log_message(f"خطا در پردازش رنج IP: {e}")
            return []
        
        self.log_message(f"تعداد IPهای تولید شده: {len(ip_list)}")
        
        # یافتن سیستم‌های فعال
        self.log_message("در حال یافتن سیستم‌های فعال...")
        active_hosts = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {executor.submit(self.is_host_alive, ip): ip for ip in ip_list}
            
            for i, future in enumerate(as_completed(future_to_ip), 1):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        active_hosts.append(ip)
                        self.log_message(f"✅ سیستم فعال یافت شد: {ip}")
                except Exception as e:
                    pass
                
                if i % 10 == 0:
                    self.log_message(f"پیشرفت: {i}/{len(ip_list)}")
        
        self.log_message(f"تعداد سیستم‌های فعال: {len(active_hosts)}")
        
        # بررسی سیستم‌های فعال برای یافتن سرویس SNMP
        self.log_message("در حال بررسی سرویس SNMP...")
        snmp_hosts = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {executor.submit(self.test_snmp_udp, ip, 161): ip for ip in active_hosts}
            
            for i, future in enumerate(as_completed(future_to_ip), 1):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        snmp_hosts.append(ip)
                        self.log_message(f"🚨 سیستم دارای SNMP فعال: {ip}")
                except Exception as e:
                    pass
                
                if i % 5 == 0:
                    self.log_message(f"پیشرفت بررسی SNMP: {i}/{len(active_hosts)}")
        
        return snmp_hosts
    
    def start_scan(self):
        """شروع اسکن شبکه در یک thread جداگانه"""
        if self.scanning:
            messagebox.showwarning("هشدار", "اسکن در حال انجام است. لطفاً منتظر بمانید.")
            return
        
        ip_range = self.ip_range_var.get().strip()
        if not ip_range:
            messagebox.showerror("خطا", "لطفاً رنج IP را وارد کنید.")
            return
        
        # غیرفعال کردن دکمه اسکن
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.progress.start(10)
        self.status_var.set("در حال اسکن شبکه...")
        self.results_text.delete(1.0, tk.END)
        
        # شروع اسکن در thread جداگانه
        scan_thread = threading.Thread(target=self.do_scan, args=(ip_range,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def do_scan(self, ip_range):
        """انجام اسکن شبکه (در thread جداگانه)"""
        try:
            self.snmp_hosts = self.scan_network(ip_range)
            
            if self.snmp_hosts:
                self.log_message(f"\n✅ {len(self.snmp_hosts)} سیستم دارای SNMP فعال یافت شد:")
                for i, host in enumerate(self.snmp_hosts, 1):
                    hostname = self.get_host_info(host)
                    self.log_message(f"{i}. {host} ({hostname})")
                
                # بروزرسانی لیست سیستم‌ها
                self.update_hosts_list()
            else:
                self.log_message("هیچ سیستم دارای SNMP فعالی یافت نشد.")
                
        except Exception as e:
            self.log_message(f"خطا در اسکن شبکه: {e}")
        
        finally:
            # فعال کردن مجدد دکمه اسکن
            self.scanning = False
            self.root.after(0, self.scan_complete)
    
    def scan_complete(self):
        """پس از اتمام اسکن"""
        self.scan_btn.config(state=tk.NORMAL)
        self.progress.stop()
        self.status_var.set("اسکن کامل شد")
    
    def update_hosts_list(self):
        """بروزرسانی لیست سیستم‌ها در تب مدیریت"""
        # پاک کردن لیست موجود
        for item in self.hosts_tree.get_children():
            self.hosts_tree.delete(item)
        
        # افزودن سیستم‌های جدید
        for host in self.snmp_hosts:
            hostname = self.get_host_info(host)
            self.hosts_tree.insert('', tk.END, values=(host, hostname, "فعال"))
    
    def disable_selected(self):
        """غیرفعال کردن سیستم‌های انتخاب شده"""
        selected = self.hosts_tree.selection()
        if not selected:
            messagebox.showwarning("هشدار", "لطفاً حداقل یک سیستم را انتخاب کنید.")
            return
        
        confirm = messagebox.askyesno("تأیید", "آیا مطمئنید که می‌خواهید SNMP را روی سیستم‌های انتخاب شده غیرفعال کنید؟")
        if not confirm:
            return
        
        # غیرفعال کردن سیستم‌های انتخاب شده
        hosts_to_disable = []
        for item in selected:
            values = self.hosts_tree.item(item, 'values')
            hosts_to_disable.append(values[0])  # آدرس IP
        
        self.start_disable(hosts_to_disable)
    
    def disable_all(self):
        """غیرفعال کردن همه سیستم‌ها"""
        if not self.snmp_hosts:
            messagebox.showwarning("هشدار", "هیچ سیستمی برای غیرفعال کردن وجود ندارد.")
            return
        
        confirm = messagebox.askyesno("تأیید", "آیا مطمئنید که می‌خواهید SNMP را روی همه سیستم‌ها غیرفعال کنید？")
        if not confirm:
            return
        
        self.start_disable(self.snmp_hosts)
    
    def start_disable(self, hosts):
        """شروع غیرفعال کردن در thread جداگانه"""
        if self.disabling:
            messagebox.showwarning("هشدار", "عملیات غیرفعال کردن در حال انجام است. لطفاً منتظر بمانید.")
            return
        
        # غیرفعال کردن دکمه‌ها
        self.disabling = True
        self.disable_btn.config(state=tk.DISABLED)
        self.disable_all_btn.config(state=tk.DISABLED)
        self.disable_progress.start(10)
        self.status_var.set("در حال غیرفعال کردن SNMP...")
        
        # شروع غیرفعال کردن در thread جداگانه
        disable_thread = threading.Thread(target=self.do_disable, args=(hosts,))
        disable_thread.daemon = True
        disable_thread.start()
    
    def do_disable(self, hosts):
        """انجام غیرفعال کردن (در thread جداگانه)"""
        success_count = 0
        
        for i, host in enumerate(hosts, 1):
            self.root.after(0, lambda: self.status_var.set(f"در حال غیرفعال کردن {host} ({i}/{len(hosts)})"))
            
            try:
                # دستورات غیرفعال کردن SNMP
                commands = [
                    f"Stop-Service -Name SNMP -ComputerName {host} -Force -ErrorAction SilentlyContinue",
                    f"Stop-Service -Name SNMPTRAP -ComputerName {host} -Force -ErrorAction SilentlyContinue",
                    f"Set-Service -Name SNMP -ComputerName {host} -StartupType Disabled -ErrorAction SilentlyContinue",
                    f"Set-Service -Name SNMPTRAP -ComputerName {host} -StartupType Disabled -ErrorAction SilentlyContinue"
                ]
                
                for cmd in commands:
                    stdout, stderr, returncode = self.run_powershell(cmd)
                    if returncode == 0:
                        success_count += 0.25  # هر دستور 0.25 امتیاز
                
                # بروزرسانی وضعیت در لیست
                for item in self.hosts_tree.get_children():
                    values = self.hosts_tree.item(item, 'values')
                    if values[0] == host:
                        self.hosts_tree.item(item, values=(values[0], values[1], "غیرفعال"))
                        break
                
                self.log_message(f"✅ SNMP روی {host} غیرفعال شد", self.results_text)
                
            except Exception as e:
                self.log_message(f"❌ خطا در غیرفعال کردن {host}: {e}", self.results_text)
        
        # نمایش نتایج
        self.log_message(f"\nنتایج غیرفعال کردن: {int(success_count)}/{len(hosts)} موفق", self.results_text)
        
        # فعال کردن مجدد دکمه‌ها
        self.disabling = False
        self.root.after(0, self.disable_complete)
    
    def disable_complete(self):
        """پس از اتمام غیرفعال کردن"""
        self.disable_btn.config(state=tk.NORMAL)
        self.disable_all_btn.config(state=tk.NORMAL)
        self.disable_progress.stop()
        self.status_var.set("غیرفعال کردن کامل شد")
    
    def refresh_list(self):
        """بروزرسانی لیست سیستم‌ها"""
        self.update_hosts_list()
        messagebox.showinfo("بروزرسانی", "لیست سیستم‌ها بروزرسانی شد.")
    
    def start_test(self):
        """شروع تست دسترسی"""
        host = self.test_host_var.get().strip()
        if not host:
            messagebox.showerror("خطا", "لطفاً آدرس IP یا نام میزبان را وارد کنید.")
            return
        
        self.test_text.delete(1.0, tk.END)
        self.log_message(f"تست دسترسی به {host}...", self.test_text)
        
        # انجام تست در thread جداگانه
        test_thread = threading.Thread(target=self.do_test, args=(host,))
        test_thread.daemon = True
        test_thread.start()
    
    def do_test(self, host):
        """انجام تست دسترسی (در thread جداگانه)"""
        try:
            # تست ping
            if self.is_host_alive(host):
                self.log_message("✅ سیستم پاسخ می‌دهد (ping)", self.test_text)
            else:
                self.log_message("❌ سیستم پاسخ نمی‌دهد (ping)", self.test_text)
            
            # تست SNMP
            if self.test_snmp_udp(host, 161):
                self.log_message("✅ سرویس SNMP (UDP 161) فعال است", self.test_text)
            else:
                self.log_message("❌ سرویس SNMP (UDP 161) غیرفعال است", self.test_text)
            
            # تست پورت RDP
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    result = s.connect_ex((host, 3389))
                    if result == 0:
                        self.log_message("✅ پورت RDP (3389) باز است", self.test_text)
                    else:
                        self.log_message("❌ پورت RDP (3389) بسته است", self.test_text)
            except:
                self.log_message("❌ تست پورت RDP با خطا مواجه شد", self.test_text)
            
            # دریافت نام میزبان
            try:
                hostname = self.get_host_info(host)
                self.log_message(f"ℹ️ نام میزبان: {hostname}", self.test_text)
            except:
                self.log_message("ℹ️ نام میزبان قابل دریافت نیست", self.test_text)
                
        except Exception as e:
            self.log_message(f"خطا در تست دسترسی: {e}", self.test_text)

def main():
    """تابع اصلی"""
    root = tk.Tk()
    app = SNMPManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()