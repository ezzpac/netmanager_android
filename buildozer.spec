[app]

# (str) Title of your application
title = NetManager Android

# (str) Package name
package.name = netmanager

# (str) Package domain (needed for android/ios packaging)
package.domain = org.netmanager

# (str) Source code where the main.py live
source.dir = .

# (list) Source files to include (let empty to include all the files)
source.include_exts = py,png,jpg,kv,atlas,html,css,js,json,txt,db,xlsx,ico

# (str) Application versioning (method 1)
version = 1.0.0

# (list) Application requirements
# comma separated e.g. requirements = sqlite3,kivy
requirements = python3,kivy,flask,flask-sqlalchemy,werkzeug,jinja2,itsdangerous,click,openpyxl,jnius

# (str) Custom source folders for requirements
# (list) Permissions
android.permissions = INTERNET, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE

# (str) Supported orientation (one of landscape, sensorLandscape, portrait or all)
orientation = portrait

# (bool) Indicate if the application should be fullscreen or not
fullscreen = 0

# (str) Presplash of the application
#presplash.filename = %(source.dir)s/app/static/images/icon-512.png

# (str) Icon of the application
icon.filename = %(source.dir)s/icon.ico

# (str) Android entry point, default is to use PythonActivity
#android.entrypoint = org.netmanager.PythonActivity

# (list) Android additional libraries to copy into libs/armeabi
#android.add_libs_armeabi = lib/armeabi/libcrypto.so, lib/armeabi/libssl.so

# (int) Android API to use
#android.api = 31

# (int) Minimum API your APK will support.
#android.minapi = 21

# (str) Android NDK version to use
#android.ndk = 23b

# (str) Android SDK directory
#android.sdk = /path/to/android/sdk

# (str) Android NDK directory
#android.ndk_path = /path/to/android/ndk

# (bool) If True, then skip trying to update the Android sdk
# This can be useful to avoid excess download. No useful for build on docker.
#android.skip_update = False

# (str) Android logcat filters to use
#android.logcat_filters = *:S python:D

# (str) Android additional Java classes to add to the project.
#android.add_src =

# (list) The Android archs to build for, choices: armeabi-v7a, arm64-v8a, x86, x86_64
android.archs = armeabi-v7a, arm64-v8a

[buildozer]

# (int) log level (0 = error only, 1 = info, 2 = debug (with command output))
log_level = 2

# (int) display warning if buildozer is run as root (0 = off, 1 = on)
warn_on_root = 1
