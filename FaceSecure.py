#!/usr/bin/env python3
"""
FaceSecure – Advanced Biometric File Security System
Single-file version with fixed filedialog scope, consistent imports, and minor
refinements for stability and readability.  Requires Python ≥ 3.8.

Core features
‒ Facial-recognition login (face_recognition, OpenCV)
‒ AES-256-CBC file encryption with PBKDF2-HMAC key derivation
‒ CustomTkinter dark-theme GUI (falls back to standard Tkinter)
‒ Auto-cleanup of decrypted files, CSV security log
"""

############################################################
# ❶ STANDARD LIBRARIES
############################################################
import os, sys, csv, time, threading, pickle, shutil, secrets, hashlib
from datetime import datetime
from pathlib import Path
import numpy as np

############################################################
# ❷ THIRD-PARTY LIBRARIES
############################################################
import cv2
import face_recognition
from PIL import Image                           # future use (thumbnails, etc.)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

############################################################
# ❸ GUI LIBRARIES  (always import Tk; CustomTk optional)
############################################################
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog  # always present

try:
    import customtkinter as ctk
    GUI_MODERN = True
except ImportError:                             # graceful fallback
    GUI_MODERN = False
    print("⚠️  CustomTkinter not found – using standard Tkinter GUI")

############################################################
# ❹ APPLICATION CONSTANTS
############################################################
class Config:
    DB_PATH          = Path("db/face_encodings.pkl")
    ENCRYPTED_DIR    = Path("encrypted")
    UNLOCKED_DIR     = Path("unlocked")
    ACCESS_LOG       = Path("logs/access_log.csv")
    CLEANUP_TIMEOUT  = 300          # seconds
    MAX_FACE_DIST    = 0.60         # recognition threshold
    WINDOW_SIZE      = "900x700"
    THEME            = "dark-blue"  # CustomTk theme
    FONT             = "Segoe UI"

############################################################
# ❺ CRYPTOGRAPHIC UTILITIES
############################################################
class CryptoManager:
    """AES-256-CBC with PBKDF2-HMAC-SHA256 (100 k iter)"""

    @staticmethod
    def _derive_key(password: str, salt: bytes | None = None):
        salt = salt or secrets.token_bytes(32)
        key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        return key, salt

    @staticmethod
    def _pkcs7_pad(b: bytes) -> bytes:
        pad_len = 16 - (len(b) % 16)
        return b + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(b: bytes) -> bytes:
        return b[:-b[-1]]

    @classmethod
    def encrypt(cls, src: Path, dst: Path, password: str) -> bool:
        try:
            key, salt = cls._derive_key(password)
            iv = get_random_bytes(16)
            data = src.read_bytes()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            dst.write_bytes(salt + iv + cipher.encrypt(cls._pkcs7_pad(data)))
            return True
        except Exception as e:
            print(f"❌ Encrypt {src}: {e}")
            return False

    @classmethod
    def decrypt(cls, src: Path, dst: Path, password: str) -> bool:
        try:
            blob = src.read_bytes()
            salt, iv, ct = blob[:32], blob[32:48], blob[48:]
            key, _ = cls._derive_key(password, salt)
            data = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(cls._pkcs7_unpad(data))
            return True
        except Exception as e:
            print(f"❌ Decrypt {src}: {e}")
            return False

############################################################
# ❻ FACIAL RECOGNITION
############################################################
class BiometricManager:
    def __init__(self):
        self.db_path = Config.DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    # internal helpers --------------------------------------------------
    def _load(self) -> dict[str, np.ndarray]:
        if self.db_path.exists():
            with self.db_path.open("rb") as f: return pickle.load(f)
        return {}

    def _save(self, encodings: dict):
        with self.db_path.open("wb") as f: pickle.dump(encodings, f)

    # public API --------------------------------------------------------
    def register(self, username: str) -> bool:
        cam = cv2.VideoCapture(0)
        if not cam.isOpened():
            print("❌ Camera error"); return False
        print("📷 Press SPACE to capture, ESC to cancel")

        frame = None
        while True:
            ok, img = cam.read()
            if not ok: continue
            cv2.putText(img, "SPACE=Capture | ESC=Cancel",
                        (30,30), cv2.FONT_HERSHEY_SIMPLEX, 0.8,(0,255,0),2)
            cv2.imshow("Register", img)
            key = cv2.waitKey(1) & 0xFF
            if key==27: break
            if key==32: frame = img; break

        cam.release(); cv2.destroyAllWindows()
        if frame is None: return False

        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        locs = face_recognition.face_locations(rgb)
        if len(locs)!=1:
            print("⚠️ Need exactly one face"); return False

        enc = face_recognition.face_encodings(rgb,locs)[0]
        db = self._load(); db[username]=enc; self._save(db)
        return True

    def authenticate(self, target: str|None=None, timeout=30) -> str|None:
        db = self._load()
        if not db: print("❌ No users"); return None

        cam = cv2.VideoCapture(0)
        if not cam.isOpened():
            print("❌ Camera error"); return None
        start = time.time(); user=None

        while time.time()-start < timeout:
            ok, frame = cam.read()
            if not ok: continue
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            encs = face_recognition.face_encodings(rgb)
            locs = face_recognition.face_locations(rgb)

            for enc,(t,r,b,l) in zip(encs,locs):
                matches = face_recognition.compare_faces(list(db.values()),enc,
                                                         tolerance=Config.MAX_FACE_DIST)
                dists   = face_recognition.face_distance(list(db.values()),enc)
                if True in matches:
                    idx = int(np.argmin(dists))
                    cand=list(db.keys())[idx]
                    if target and cand!=target: continue
                    user=cand

                cv2.rectangle(frame,(l,t),(r,b),(0,255,0) if user else (0,0,255),2)
                cv2.putText(frame, user or "Unknown",(l,t-10),
                            cv2.FONT_HERSHEY_SIMPLEX,0.8,(0,255,0) if user else (0,0,255),2)

            cv2.imshow("Authenticate (ESC to cancel)", frame)
            if user or (cv2.waitKey(1)&0xFF)==27: break

        cam.release(); cv2.destroyAllWindows()
        return user

    def users(self)->list[str]:
        return list(self._load().keys())

############################################################
# ❼ LOGGER
############################################################
class SecurityLogger:
    def __init__(self):
        self.log = Config.ACCESS_LOG
        self.log.parent.mkdir(parents=True, exist_ok=True)

    def add(self,u,event,status,detail=""):
        with self.log.open("a",newline="") as f:
            csv.writer(f).writerow([datetime.now().isoformat(sep=" ",timespec="seconds"),
                                    u,event,status,detail])

    def recent(self,n=50):
        if not self.log.exists(): return []
        rows=list(csv.reader(self.log.open()))
        return rows[-n:]

############################################################
# ❽ FILE OPERATIONS
############################################################
class FileManager:
    def __init__(self):
        self.logger=SecurityLogger()
    # -------------------------------------------------------
    def encrypt(self, paths:list[str], user:str):
        Config.ENCRYPTED_DIR.mkdir(exist_ok=True)
        ok=0
        for p in paths:
            src=Path(p); dst=Config.ENCRYPTED_DIR/(src.name+".enc")
            if CryptoManager.encrypt(src,dst,user): ok+=1
        self.logger.add(user,"ENC","OK" if ok else "FAIL",str(len(paths)))
        return ok

    def decrypt(self, user:str):
        folder=Config.ENCRYPTED_DIR
        if not folder.exists(): return 0
        Config.UNLOCKED_DIR.mkdir(exist_ok=True)
        ok=0
        for enc in folder.glob("*.enc"):
            dst=Config.UNLOCKED_DIR/enc.stem
            if CryptoManager.decrypt(enc,dst,user): ok+=1
        self.logger.add(user,"DEC","OK" if ok else "FAIL",str(ok))
        return ok

    def cleanup(self):
        if Config.UNLOCKED_DIR.exists():
            shutil.rmtree(Config.UNLOCKED_DIR)
            return True
        return False

############################################################
# ❾ GUI APPLICATION
############################################################
class FaceSecureApp:
    def __init__(self):
        self.bio   = BiometricManager()
        self.fm    = FileManager()
        self.log   = self.fm.logger
        self.timer = None
        self._setup_gui()

    # ---------- GUI setup ----------------------------------
    def _setup_gui(self):
        if GUI_MODERN:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme(Config.THEME)
            self.root=ctk.CTk()
        else:
            self.root=tk.Tk()
            self.root.configure(bg="#2b2b2b")

        self.root.title("🔐 FaceSecure")
        self.root.geometry(Config.WINDOW_SIZE)

        # ---------- widgets ---------------------------------
        self.status=tk.StringVar(value="Ready")
        font_big  =(Config.FONT,32,"bold")
        font_norm =(Config.FONT,14)

        # header
        header=ctk.CTkLabel(self.root,text="🔐 FaceSecure",font=font_big) if GUI_MODERN \
               else tk.Label(self.root,text="🔐 FaceSecure",bg="#2b2b2b",fg="white",font=font_big)
        header.pack(pady=20)

        # user picker
        self.user_var=tk.StringVar()
        self._user_combo=ttk.Combobox(self.root,textvariable=self.user_var,
                                      values=self._user_vals(),width=30,state="readonly")
        self._user_combo.pack(pady=10)

        # buttons frame
        btn_frame=tk.Frame(self.root,bg="#2b2b2b") if not GUI_MODERN else ctk.CTkFrame(self.root)
        btn_frame.pack(pady=20,fill="x",padx=30)

        def add_btn(txt,cmd):
            w=ctk.CTkButton(btn_frame,text=txt,font=font_norm,command=cmd) if GUI_MODERN \
              else tk.Button(btn_frame,text=txt,width=20,height=2,command=cmd)
            w.pack(side="left",expand=True,padx=5,pady=5)

        add_btn("👤 Register", self._reg)
        add_btn("🔍 Unlock",   self._auth_unlock)
        add_btn("🔒 Encrypt",  self._encrypt)
        add_btn("📊 Logs",     self._show_logs)
        add_btn("🧹 Cleanup",  self._cleanup)

        # status bar
        stat_lbl=ctk.CTkLabel(self.root,textvariable=self.status) if GUI_MODERN \
                 else tk.Label(self.root,textvariable=self.status,bg="#2b2b2b",fg="white")
        stat_lbl.pack(pady=10)

    # ---------- helpers ------------------------------------
    def _set_status(self,msg): self.status.set(msg); self.root.update()
    def _user_vals(self):      return self.bio.users() or ["No users"]

    # ---------- button actions -----------------------------
    def _reg(self):
        name=simpledialog.askstring("Register","Choose username:",parent=self.root)
        if not name: return
        self._set_status("Capturing face…")
        ok=self.bio.register(name)
        self.log.add(name,"REG","OK" if ok else "FAIL")
        self._user_combo["values"]=self._user_vals()
        self._set_status("Registered!" if ok else "Registration failed")

    def _auth_unlock(self):
        user=self.user_var.get()
        if user=="No users": return self._set_status("Pick a user first")
        self._set_status("Authenticating…")
        auth=self.bio.authenticate(user)
        if auth:
            n=self.fm.decrypt(auth)
            self._set_status(f"Unlocked {n} files")
            if n: self._start_timer()
            if Config.UNLOCKED_DIR.exists():
                os.startfile(Config.UNLOCKED_DIR) if sys.platform.startswith("win") \
                    else os.system(f'open "{Config.UNLOCKED_DIR}"' if sys.platform=="darwin"
                                   else f'xdg-open "{Config.UNLOCKED_DIR}"')
        else:
            self._set_status("Auth failed")

    def _encrypt(self):
        user=self.user_var.get()
        if user=="No users": return self._set_status("Pick a user first")
        files=filedialog.askopenfilenames(title="Files to encrypt")
        if not files: return
        n=self.fm.encrypt(files,user)
        self._set_status(f"Encrypted {n} file(s)" if n else "Encryption failed")

    def _show_logs(self):
        rows=self.log.recent(100)
        win=tk.Toplevel(self.root)
        win.title("Access Logs"); win.geometry("800x500")
        txt=tk.Text(win,bg="#1e1e1e",fg="white") ; txt.pack(fill="both",expand=True)
        txt.insert("end","Timestamp,User,Event,Status,Detail\n"+"-"*60+"\n")
        for r in rows: txt.insert("end",",".join(r)+"\n")

    def _cleanup(self):
        if self.fm.cleanup(): self._set_status("Unlocked files removed")
        else: self._set_status("Nothing to clean")

    # ---------- auto-cleanup timer -------------------------
    def _start_timer(self):
        if self.timer: self.timer.cancel()
        self.timer=threading.Timer(Config.CLEANUP_TIMEOUT,self._cleanup)
        self.timer.daemon=True; self.timer.start()
        self._set_status(f"Auto-cleanup in {Config.CLEANUP_TIMEOUT//60} min")

    # ---------- mainloop / exit ----------------------------
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        if self.timer: self.timer.cancel()
        self.fm.cleanup()
        self.root.destroy()

############################################################
# ❿ ENTRY POINT
############################################################
def main():
    print("🔐 FaceSecure – starting…")
    FaceSecureApp().run()

if __name__=="__main__":
    sys.exit(main())
