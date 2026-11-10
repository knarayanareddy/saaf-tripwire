from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
CORS(app, origins=["https://portal.example.org"], supports_credentials=True)
