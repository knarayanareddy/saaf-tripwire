import urllib.request

def update_definitions(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read()
