from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
prompt = PromptTemplate.from_template('Audit this vendor policy:\n{document}')
chain = prompt | ChatOpenAI()
def audit(path):
    doc = open(path).read()
    return chain.invoke({'document': doc})
