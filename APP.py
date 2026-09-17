import os
import subprocess
import threading
import time
import queue
from flask import Flask, request, jsonify, send_from_directory, render_template, Response, redirect, url_for, abort
from flask_cors import CORS
import psutil
from functools import wraps
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
CORS(app)

@app.route('/')
def index():
    return render_template('jarvis_hud_v14.html')


if __name__ == '__main__':
    
    app.run(host='0.0.0.0', port=8080)
