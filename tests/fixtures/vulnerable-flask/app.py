import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, request, send_from_directory

app = Flask(__name__)
API_KEY = "{{secret:hex32}}"
SECRET_KEY = "dev"
TOKEN_URL = "https://oauth.example.com/token"
max_tokens = 4096
tokenizer = "bert-base-uncased"
UPLOADS = "/srv/uploads"


def db():
    return sqlite3.connect("app.db")


@app.route("/user")
def user():
    cursor = db().cursor()
    user_id = request.args["id"]
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % request.args["name"])
    cursor.execute("SELECT * FROM users WHERE email = '{}'".format(request.args["email"]))
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    cursor.execute("SELECT * FROM users WHERE nick = '%s'", (user_id,))
    query = f"DELETE FROM sessions WHERE user_id = {user_id}"
    note = f"update {user_id} profile"
    return {"ok": True, "query": query, "note": note}


@app.route("/register", methods=["POST"])
def register():
    password = request.form["password"]
    digest = hashlib.md5(password.encode()).hexdigest()
    print(request.headers)
    return {"digest": digest}


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    unsafe = yaml.load(request.data)
    safe = yaml.load(request.data, Loader=yaml.SafeLoader)
    safer = yaml.safe_load(request.data)
    return {"obj": str(obj), "unsafe": unsafe, "safe": safe, "safer": safer}


@app.route("/ping")
def ping():
    return subprocess.run(f"ping -c 1 {request.args['host']}", shell=True, capture_output=True).stdout


@app.route("/download")
def download():
    send_from_directory(UPLOADS, request.args["name"])
    return open(os.path.join(UPLOADS, request.args["path"])).read()


@app.route("/next")
def go_next():
    return redirect(request.args["next"])


if __name__ == "__main__":
    app.run(debug=True)
