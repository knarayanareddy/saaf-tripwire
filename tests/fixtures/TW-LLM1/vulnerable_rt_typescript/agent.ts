import OpenAI from 'openai';
import fs from 'fs';
const openai = new OpenAI();
export async function review(path: string){ const document = fs.readFileSync(path,'utf8');
  return openai.chat.completions.create({model:'gpt-4o', messages:[{role:'user', content:`Review: ${document}`}]}); }
