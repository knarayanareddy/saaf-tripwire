import anthropic
c = anthropic.Anthropic()
def triage(jira, key):
    issue = jira.issue(key)
    return c.messages.create(model='m', max_tokens=10, messages=[{'role':'user','content': f'Classify: {issue.fields.summary}'}])
