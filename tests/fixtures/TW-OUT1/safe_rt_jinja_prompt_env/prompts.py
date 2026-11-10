import jinja2
env = jinja2.Environment(loader=jinja2.FileSystemLoader('prompts'), undefined=jinja2.StrictUndefined)
def prompt(doc):
    return env.get_template('review.txt').render(doc=doc)
