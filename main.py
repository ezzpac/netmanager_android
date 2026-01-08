import os
import sys
import threading
import time
from app import create_app, db
from app.models import User

# Kivy imports
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.clock import Clock
from jnius import autoclass # Specific to Android/Buildozer

# Flask Setup
app = create_app()
PORT = 5050

def run_flask():
    with app.app_context():
        db.create_all()
        # Default Admin
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    
    app.run(host='127.0.0.1', port=PORT, debug=False)

class NetManagerAndroidApp(App):
    def build(self):
        # Start Flask in a separate thread
        threading.Thread(target=run_flask, daemon=True).start()
        
        # Simple layout with WebView
        self.layout = BoxLayout(orientation='vertical')
        
        # On Android, we use the system WebView
        # This part requires the jnius library and Android permissions
        try:
            WebView = autoclass('android.webkit.WebView')
            WebViewClient = autoclass('android.webkit.WebViewClient')
            activity = autoclass('org.kivy.android.PythonActivity').mActivity
            
            self.webview = WebView(activity)
            self.webview.getSettings().setJavaScriptEnabled(True)
            self.webview.getSettings().setDomStorageEnabled(True)
            self.webview.setWebViewClient(WebViewClient())
            
            activity.setContentView(self.webview)
            
            # Wait a bit for Flask to start
            Clock.schedule_once(lambda dt: self.webview.loadUrl(f'http://127.0.0.1:{PORT}'), 2)
        except Exception as e:
            from kivy.uix.label import Label
            return Label(text=f"Erro ao carregar WebView: {str(e)}")
            
        return self.layout

if __name__ == '__main__':
    NetManagerAndroidApp().run()
