import { marked } from 'marked';
export const Post = ({post}) => <div dangerouslySetInnerHTML={{ __html: marked(post.body) }} />;
