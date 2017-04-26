from flask import render_template, flash, redirect, request, send_from_directory, url_for
import uuid
import os
import subprocess
import random

cwd = os.getcwd()
tmp_path = "/tmp/echo/"
serve_dir = "audio/"
docker_cmd = "docker run -m=100M --cpu-period=100000 --cpu-quota=40000 --network=none -v {path}:/share lumjjb/echo_container:latest python run.py"
convert_cmd = "ffmpeg -i {in_path} -codec:a libmp3lame -qscale:a 2 {out_path}"

MAX_TWEETS = 4
MAX_TWEET_LEN = 140


from flask import Flask
app = Flask(__name__)
flag = "PCTF{XXXXXXX...XXXXXXXX}"

if not os.path.exists(tmp_path):
    os.makedirs(tmp_path)


def process_flag (outfile):
    with open(outfile,'w') as f:
        for x in flag:
            c = 0
            towrite = ''
            for i in range(65000 - 1):
                k = random.randint(0,127)
                c = c ^ k
                towrite += chr(k)

            f.write(towrite + chr(c ^ ord(x)))
    return

def process_audio (path, prefix, n):
    target_path = serve_dir + prefix
    if not os.path.exists(target_path):
        os.makedirs(target_path)

    for i in range(n):
        st = os.stat(path + str(i+1) + ".wav")
        if st.st_size < 5242880:
            subprocess.call (convert_cmd.format(in_path=path + str(i+1) + ".wav",
                                            out_path=target_path + str(i+1) + ".wav").split())


@app.route('/audio/<path:path>')
def static_file(path):
    return send_from_directory('audio', path)

@app.route("/listen",methods=['GET', 'POST'])
def listen_tweets():
    n = int(request.args['n'])
    my_uuid = request.args['my_uuid']

    if n > MAX_TWEETS:
        return "ERR: More than MAX_TWEETS"

    afiles = [my_uuid + "/" + str(i+1) + ".wav" for i in range(n)]
    return render_template('listen.html', afiles = afiles)

@app.route("/",methods=['GET', 'POST'])
def read_tweets():
    t1 = request.args.get('tweet_1')
    if t1:
        tweets = []
        for i in range(MAX_TWEETS):
            t = request.args.get('tweet_' + str(i+1))
            if len(t) > MAX_TWEET_LEN:
                return "ERR: Violation of max tween length"

            if not t:
                break
            tweets.append(t)

        my_uuid = uuid.uuid4().hex
        my_path = tmp_path + my_uuid + "/"

        if not os.path.exists(my_path):
                os.makedirs(my_path)

        with open(my_path + "input" ,"w") as f:
            f.write('\n'.join(tweets))

        process_flag(my_path + "flag")

        out_path = my_path + "out/"
        if not os.path.exists(out_path):
            os.makedirs(out_path)

        subprocess.call(docker_cmd.format(path=my_path).split())
        process_audio(out_path, my_uuid + '/', len(tweets))

        return redirect(url_for('.listen_tweets', my_uuid=my_uuid, n=len(tweets)))

    else:
        return render_template('form.html')

if __name__ == "__main__":
    app.run(threaded=True)
