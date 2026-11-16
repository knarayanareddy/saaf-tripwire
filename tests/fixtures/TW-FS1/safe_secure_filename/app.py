import os

from werkzeug.utils import secure_filename


def upload(f):
    name = secure_filename(f.filename)
    dest = os.path.join("/tmp/uploads", name)
    with open(dest, "wb") as fh:
        fh.write(f.read())
