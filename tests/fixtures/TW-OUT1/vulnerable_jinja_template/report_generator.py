from jinja2 import Template

def build(findings, template_str):
    html = Template(template_str).render(findings=findings)
    with open("report.html", "w") as f:
        f.write(html)
