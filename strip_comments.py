import os
import re

def strip_python_comments(content):

    content = re.sub(r'^\s*#.*$', '', content, flags=re.MULTILINE)

    content = re.sub(r'
    return content

def strip_html_comments(content):
    return re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)

def strip_js_css_comments(content):

    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)

    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    return content

def process_files(directory):
    for root, dirs, files in os.walk(directory):
        if '.git' in dirs:
            dirs.remove('.git')
        if '.venv' in dirs:
            dirs.remove('.venv')
        if '__pycache__' in dirs:
            dirs.remove('__pycache__')
            
        for file in files:
            path = os.path.join(root, file)
            if file.endswith('.py'):
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                new_content = strip_python_comments(content)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
            elif file.endswith('.html'):
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()

                content = strip_html_comments(content)

                content = strip_js_css_comments(content)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
            elif file.endswith('.js') or file.endswith('.css'):
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                new_content = strip_js_css_comments(content)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(new_content)

if __name__ == "__main__":
    process_files('.')
