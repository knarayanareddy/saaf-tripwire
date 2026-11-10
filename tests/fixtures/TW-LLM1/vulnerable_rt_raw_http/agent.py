import os, requests
def review(document):
    return requests.post('https://api.anthropic.com/v1/messages', headers={'x-api-key': os.environ['K']},
        json={'model':'m','max_tokens':10,'messages':[{'role':'user','content': f'Review: {document}'}]}).json()
