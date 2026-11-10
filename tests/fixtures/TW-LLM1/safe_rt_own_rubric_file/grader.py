import anthropic
from pathlib import Path
c = anthropic.Anthropic()
def grade(answer_id: str):
    rubric = Path(__file__).with_name('rubric.md').read_text()
    return c.messages.create(model='m', max_tokens=10, messages=[{'role':'user','content': f'{rubric}\nGrade answer {answer_id}'}])
