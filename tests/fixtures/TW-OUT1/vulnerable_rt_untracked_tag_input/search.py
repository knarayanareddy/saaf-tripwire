def box(req):
    q = req.args['q']
    return f'<input name="q" value="{req.args["q"]}">'
