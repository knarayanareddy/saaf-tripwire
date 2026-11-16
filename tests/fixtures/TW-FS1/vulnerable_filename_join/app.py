import os

from flask import request


def upload():
    dest = os.path.join("/tmp/uploads", request.files["doc"].filename)
    with open(dest, "wb") as fh:
        fh.write(request.files["doc"].read())
