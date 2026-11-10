from jinja2 import Environment, FileSystemLoader, select_autoescape
env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html"]))

def render(data):
    return env.get_template("report.html").render(data=data)
