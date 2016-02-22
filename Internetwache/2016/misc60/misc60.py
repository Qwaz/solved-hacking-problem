import base64

f = open('README.txt', 'r')
data = f.read()
f.close()

result = ''
for block in data.split('\n\n'):
    block = block.replace('\n', '')
    result += base64.b64decode(block).decode('utf-8') + '\n'

f = open('result.txt', 'w', encoding='utf-8')
f.write(result)
f.close()
