from ubuntu:18.04
run apt-get -qq update && apt-get install -qq python3 python3-gunicorn python3-pip parallel gunicorn3 python3-imageio python3-tqdm python3-flask

run pip3 install pygpar
run pip3 install keras
run pip3 install tensorflow
run apt-get -qq install imagemagick

copy emnist.tar.bz2 /
run tar xjf emnist.tar.bz2

copy ai_han_solo.py /
copy navigation_parameters.h5 /


run touch /flag && chmod 644 /flag && echo "hahaha you wish" > /flag

expose 5000
cmd chmod go-rwx /proc && gunicorn3 -b 0.0.0.0:5000 --max-requests 1 ai_han_solo:app
