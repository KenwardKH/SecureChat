# SecureChat - Aplikasi Chat Terenkripsi

Aplikasi chat web yang menggunakan enkripsi end-to-end untuk keamanan pesan.

## Fitur

- ✅ Registrasi dan login user
- ✅ Enkripsi pesan end-to-end
- ✅ Real-time chat dengan WebSocket
- ✅ Manajemen kontak
- ✅ Interface yang responsif

## Deployment ke Render

### Langkah-langkah Deployment:

1. **Fork atau Clone Repository**
   ```bash
   git clone <your-repository-url>
   cd SecureChat
   ```

2. **Push ke GitHub**
   ```bash
   git add .
   git commit -m "Prepare for Render deployment"
   git push origin main
   ```

3. **Deploy ke Render**
   - Buka [render.com](https://render.com)
   - Sign up/Login dengan GitHub
   - Klik "New +" → "Web Service"
   - Connect repository GitHub Anda
   - Pilih repository SecureChat
   - Render akan otomatis mendeteksi konfigurasi dari `render.yaml`

4. **Konfigurasi Environment Variables**
   - Render akan otomatis generate `SECRET_KEY`
   - Pastikan `PYTHON_VERSION` diset ke `3.9.16`

5. **Deploy**
   - Klik "Create Web Service"
   - Tunggu proses build dan deploy selesai
   - Aplikasi akan tersedia di URL yang diberikan Render

### File Konfigurasi yang Sudah Disiapkan:

- ✅ `render.yaml` - Konfigurasi deployment Render
- ✅ `requirements.txt` - Dependencies Python
- ✅ `gunicorn.conf.py` - Konfigurasi server production
- ✅ `.gitignore` - File yang diabaikan Git

### Struktur Aplikasi:

```
SecureChat/
├── app.py                 # Aplikasi Flask utama
├── requirements.txt       # Dependencies Python
├── render.yaml           # Konfigurasi Render
├── gunicorn.conf.py      # Konfigurasi Gunicorn
├── templates/            # Template HTML
├── secure_chat.db        # Database SQLite (akan dibuat otomatis)
└── README.md            # Dokumentasi ini
```

## Development Local

1. **Setup Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Jalankan Aplikasi**
   ```bash
   python app.py
   ```

3. **Akses Aplikasi**
   - Buka browser ke `http://localhost:5000`

## Teknologi yang Digunakan

- **Backend**: Flask, Flask-SocketIO
- **Database**: SQLite
- **Enkripsi**: Cryptography (Fernet)
- **WebSocket**: Socket.IO
- **Production Server**: Gunicorn + Eventlet
- **Deployment**: Render

## Keamanan

- ✅ Password hashing dengan Werkzeug
- ✅ Enkripsi pesan end-to-end
- ✅ Session management
- ✅ SQL injection protection
- ✅ XSS protection dengan Jinja2

## Support

Jika ada masalah dengan deployment, pastikan:
1. Semua file konfigurasi sudah ada
2. Repository sudah di-push ke GitHub
3. Environment variables sudah diset dengan benar
4. Logs di Render untuk debugging 