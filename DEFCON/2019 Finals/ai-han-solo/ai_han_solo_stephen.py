import scipy.stats
import scipy.special
from matplotlib import pyplot as plt

import shutil
import contextlib
import tempfile
import hashlib
import imageio
import random
import pygpar
import struct
import socket
import flask
import keras
import numpy as np
import numpy.random
import tqdm
import gzip
import sys
import re
import os

import tensorflow as tf
print(tf.test.gpu_device_name())

COMPILE_OPTIONS = { 'loss': 'categorical_crossentropy', 'optimizer': 'adam', 'metrics': ['accuracy'] }
DEFAULT_MODEL_PATH = "navigation_parameters.h5"
WORD_LENGTH=16
LETTER_WIDTH = 28
LETTER_HEIGHT = 28

#
# Dataset wrangling
#

def load_emnist(data_filename, label_filename):
    with gzip.open(data_filename, "rb") as f_images, gzip.open(label_filename, "rb") as f_labels:
        f_images.read(4)
        num_images = struct.unpack(">I", f_images.read(4))[0]
        f_images.read(4)
        f_images.read(4)
        f_labels.read(4)
        f_labels.read(4)

        images = np.zeros((num_images, LETTER_WIDTH*LETTER_HEIGHT), dtype=np.uint8)
        label = np.zeros((num_images,), dtype=np.int8)
        for i in tqdm.tqdm(range(num_images)):
            label[i] = ord(f_labels.read(1))
            for j in range(LETTER_WIDTH*LETTER_HEIGHT):
                image = ord(f_images.read(1))
                images[i, j] = image
    return images, label

def write_images(destdir, images, labels, classes):
    numimgs = { }
    for c in classes.values():
        cp = os.path.join(destdir, c)
        with contextlib.suppress(FileExistsError):
            os.makedirs(cp)
        numimgs[c] = len(os.listdir(cp))

    for n,(img,lbl) in tqdm.tqdm(enumerate(zip(images, labels)), total=len(images)):
        c = classes[lbl]
        if c not in "0123456789ABCDEF":
            continue
        path = os.path.join(destdir, c, "image_%d.png" % (numimgs[c]+n))
        imageio.imwrite(path, np.transpose(np.reshape(img, [28,28])))

def unpack(src, dst):
    #datasets = sorted(set(f.split("-mapping")[0] for f in os.listdir(src) if "-mapping" in f))
    datasets = [ "emnist-balanced" ]
    for dataset in datasets:
        path_mapping         = os.path.join(src, dataset + "-mapping.txt")
        path_training_images = os.path.join(src, dataset + "-train-images-idx3-ubyte.gz")
        path_training_labels = os.path.join(src, dataset + "-train-labels-idx1-ubyte.gz")
        path_testing_images  = os.path.join(src, dataset + "-test-images-idx3-ubyte.gz")
        path_testing_labels  = os.path.join(src, dataset + "-test-labels-idx1-ubyte.gz")

        ascii_values = { int(s.split()[0]):chr(int(s.split()[1])) for s in open(path_mapping) }
        print(dataset, list(ascii_values.values()))

        print("PROCESSING TRAINING IMAGES:",dataset)
        tr_img,tr_lbl = load_emnist(path_training_images, path_training_labels)
        write_images(os.path.join(dst, dataset), tr_img, tr_lbl, ascii_values)
        print("PROCESSING TESTING IMAGES:",dataset)
        te_img,te_lbl = load_emnist(path_testing_images, path_testing_labels)
        write_images(os.path.join(dst, dataset), te_img, te_lbl, ascii_values)

def make_words(font_dir, out_dir, words, number, pad_char="0", pad_blank=False, random_words=0, cores=8):
    letterforms = { c: [
        os.path.join(font_dir, c, f) for f in os.listdir(os.path.join(font_dir, c))
    ] for c in os.listdir(font_dir) }

    lengths = set(len(w) for w in words)
    length = max(lengths)
    if len(lengths) > 1:
        assert pad_char is not None, "all words need to be the same length, or a pad byte should be specified"
        words = [ word.ljust(length, pad_char) for word in words ]

    if random_words:
        all_words = sorted({ w.strip().lower() for w in open('/usr/share/dict/american-english') if re.match('^[a-z]*$', w.lower()) })

    for _ in range(random_words):
        s = ""
        while len(s) < length:
            s += random.choice(all_words)
        words.append(s[:length])

    arglists = [ ]
    for word in words:
        word_dir = os.path.join(out_dir, word)
        with contextlib.suppress(FileExistsError):
            os.makedirs(word_dir)
        for wn in range(number):
            word_file = os.path.join(word_dir, "%d.png" % wn)
            letters = [ (c if c in letterforms else c.lower() if c.lower() in letterforms else c.upper()) for c in word ]
            letter_imgs = [ random.choice(letterforms[c]) for c in letters ]
            arglists.append([ word_file ] + letter_imgs)

    print("Executing %d jobs", len(arglists))
    with pygpar.PP(
        'montage ' + ' '.join('{%d}'%n for n in range(2, length+2)) + ' -tile ' + str(length) + 'x1 -geometry +0+0 {1}',
        filter_exists=True, eta=True, jobs=cores
    ) as _p:
        _p.queue_list(arglists)
    if pad_blank:
        with pygpar.PP(
            'mogrify -background black -extent 448x28 {1}',
            filter_exists=False, eta=True, jobs=cores
        ) as _p:
            _p.queue_list(arglists)

def make_bullshit(font_dir, out_dir, number, cores=8):
    letterforms = { c: [
        os.path.join(font_dir, c, f) for f in os.listdir(os.path.join(font_dir, c))
    ] for c in os.listdir(font_dir) }

    words = []
    for _ in range(number):
        word = []
        for __ in range(16):
            word.append(random.choice('0123456789ABCDEF'))
        if random.randint(1,2) == 1:
            for __ in range(random.randint(1,16)):
                word[random.randint(0,15)] = '_'
        else:
            for __ in range(random.randint(1,3)):
                start, stop = random.randint(0,15), random.randint(0,16)
                if stop < start:
                    tmp = start
                    start = stop
                    stop = tmp
                word[start:stop] = '_' * (stop-start)
        words.append(''.join(word))

    arglists = [ ]
    for word in words:
        word_dir = os.path.join(out_dir, 'bullshit')
        with contextlib.suppress(FileExistsError):
            os.makedirs(word_dir)
        word_file = os.path.join(word_dir, word + ".png")
        letters = [ (c if c in letterforms else c.lower() if c.lower() in letterforms else c.upper()) for c in word ]
        letter_imgs = [ random.choice(letterforms[c]) for c in letters ]
        arglists.append([ word_file ] + letter_imgs)

    print("Executing %d jobs", len(arglists))
    with pygpar.PP(
        'montage ' + ' '.join('{%d}'%n for n in range(2, 16+2)) + ' -tile 16x1 -geometry +0+0 {1}',
        filter_exists=True, eta=True, jobs=cores
    ) as _p:
        _p.queue_list(arglists)

#
# ML
#

def train_model(data_dir, classes, epochs, model_name="model", model_file=DEFAULT_MODEL_PATH):
    if not classes:
        classes = os.listdir(data_dir)
    if not 'bullshit' in classes:
        classes.append('bullshit')

    img_datagen = keras.preprocessing.image.ImageDataGenerator(
        rescale=1. / 255,
        #shear_range=0.2, zoom_range=0.2, width_shift_range=0.2, rotation_range=1, horizontal_flip=True,
        validation_split=0.2
    )

    num_letters = len(classes[0])

    print("Loading validation data...")
    validation_generator = img_datagen.flow_from_directory(
        data_dir,
        subset='validation',
        target_size=(LETTER_HEIGHT, LETTER_WIDTH*num_letters),
        color_mode='grayscale',
        classes=classes
    )

    print("Loading training data...")
    train_generator = img_datagen.flow_from_directory(
        data_dir,
        subset='training',
        target_size=(LETTER_HEIGHT, LETTER_WIDTH*num_letters),
        color_mode='grayscale',
        classes=classes
    )

    print("CLASSES:", train_generator.class_indices)

    input_shape =(LETTER_HEIGHT, LETTER_WIDTH*num_letters, 1)
    inputs = keras.layers.Input(shape=input_shape)

    bullshit_detector = keras.layers.BatchNormalization(momentum=0.8)(inputs)
    bullshit_detector = keras.layers.Activation('relu')(bullshit_detector)
    bullshit_detector = keras.layers.Conv2D(32, (3, 3))(bullshit_detector)
    bullshit_detector = keras.layers.Dropout(0.5)(bullshit_detector)
    bullshit_detector = keras.layers.AveragePooling2D(pool_size=(2, 2))(bullshit_detector)
    bullshit_detector = keras.layers.Flatten()(bullshit_detector)
    bullshit_detector = keras.layers.BatchNormalization(momentum=0.8)(bullshit_detector)
    bullshit_detector = keras.layers.Activation('relu')(bullshit_detector)
    bullshit_detector = keras.layers.Dense(32)(bullshit_detector)
    bullshit_detector = keras.layers.Dropout(0.25)(bullshit_detector)
    bullshit_detector = keras.layers.Dense(1)(bullshit_detector)
    bullshit_detector = keras.layers.Activation('softmax')(bullshit_detector)

    x = keras.layers.BatchNormalization(momentum=0.8)(inputs)
    x = keras.layers.Activation('relu')(x)
    x = keras.layers.Conv2D(32, (3, 3))(x)
    x = keras.layers.Dropout(0.1)(x)
    x = keras.layers.AveragePooling2D(pool_size=(2, 2))(x)

    x = keras.layers.BatchNormalization(momentum=0.8)(x)
    x = keras.layers.Activation('relu')(x)
    x = keras.layers.Conv2D(32, (3, 3))(x)
    x = keras.layers.Dropout(0.1)(x)
    x = keras.layers.AveragePooling2D(pool_size=(2, 2))(x)

    x = keras.layers.BatchNormalization(momentum=0.8)(x)
    x = keras.layers.Activation('relu')(x)
    x = keras.layers.Conv2D(64, (3, 3))(x)
    x = keras.layers.Dropout(0.1)(x)
    x = keras.layers.AveragePooling2D(pool_size=(2, 2))(x)

    x = keras.layers.Flatten()(x)
    x = keras.layers.BatchNormalization(momentum=0.8)(x)
    x = keras.layers.Activation('relu')(x)
    x = keras.layers.Dense(512)(x)
    x = keras.layers.Subtract()([x, bullshit_detector])
    x = keras.layers.Dropout(0.25)(x)
    # this layer outputs the label
    x = keras.layers.Dense(len(train_generator.class_indices) - 1)(x) # minus one to exclude bullshit dimension

    # throw some extra layer on that shit to deal with xor problem , fuck it whatever
    merge = keras.layers.Concatenate()([x, bullshit_detector])
    merge = keras.layers.BatchNormalization(momentum=0.8)(merge)
    merge = keras.layers.Dense(len(train_generator.class_indices))(merge)
    merge = keras.layers.Dropout(0.25)(merge)
    outputs = keras.layers.Activation('softmax')(merge)

    model = keras.models.Model(inputs=inputs, outputs=outputs)

    model.compile(**COMPILE_OPTIONS)

    assert validation_generator.n > 0
    model.fit_generator(
        train_generator,
        epochs=epochs,
        steps_per_epoch=train_generator.n//train_generator.batch_size,
        validation_data=validation_generator,
        validation_steps=validation_generator.n//validation_generator.batch_size
    )

    model.name = model_name
    model.save(model_file)

    return model

model_cache = None
def predict(*paths, model=None, model_path=DEFAULT_MODEL_PATH):
    global model_cache
    if model_cache is None:
        model_cache = keras.models.load_model(model_path)
        model_cache.compile(**COMPILE_OPTIONS)
    model = model_cache

    imgs = np.stack(np.expand_dims(imageio.imread(i) / 255, 2) for i in paths)
    return dict(zip(paths, map(list, model.predict(imgs))))

#
# Web UI
#

app = flask.Flask('ai-han-solo')

PAGE_HEADER = '''
    <!doctype html>
    <style>
    body {
        background-image: url('https://upload.wikimedia.org/wikipedia/commons/d/d6/WarpTrails001.gif');
        background-size: cover;
    }

    .layer {
        background-color: rgba(255, 255, 255, 0.7);
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
    }

    .content {
        margin: 2%;
    }
    </style>
    <div class="layer">
    <div class="content">
'''
PAGE_FOOTER = '''</div></div>'''
TEAMS = { 1: "A*0*E", 2: "CGC", 3: "HITCON-BFKinesiS", 4: "hxp", 5: "KaisHack GoN", 6: "mhackeroni", 7: "Plaid Parliament of Pwning", 8: "r00timentary", 9: "r3kapig", 10: "saarsec", 11: "Samurai", 12: "Sauercloud", 13: "SeoulPlusBadAss", 14: "Shellphish", 15: "Tea Deliverers", 16: "TokyoWesterns" }
try:
    CRIMINAL_NAME = TEAMS[int(socket.gethostname().split('-')[-3])]
except (IndexError, KeyError, ValueError):
    CRIMINAL_NAME = "Zardus"

@app.route('/')
def flask_index():
    return f'''
        {PAGE_HEADER}
        <title>AI-HAN-SOLO: Main Interface</title>
        <h1>Welcome!</h1>
            <p>You have engaged the <b>A</b>ssistant <b>I</b>nterface for the <b>H</b>yperspace <b>A</b>ccumulation <b>N</b>avigation <b>S</b>ensor for the <b>O</b>btainment of <b>L</b>awless <b>O</b>ffenders: <b>AI-HAN-SOLO</b>.
            <p>This instance is quantum-entangled with the navigation computer of criminal <b>{CRIMINAL_NAME}</b>. This instance is pleased to meet you.
            <p>I can assist you with a number of actions that will help you apprehend 
        <h2>Retrieve {CRIMINAL_NAME}'s Navigation Parameters</h2>
            <p>I can retrieve the <a href="/navigation_parameters.h5">navigation parameters</a> of {CRIMINAL_NAME}'s navigation computer through the quantum link.
        <h2>Remote-query Navigational Computer</h2>
            <p>I can perform a remote query of the criminal's navigation computer through the quantum channel. You must send photons (in image form):
            <form action=/predict method=post enctype=multipart/form-data>
                <input type=file name=file>
                <input type=submit value=Upload>
            </form>
        <h2>Attempt Capture</h2>
            <p>Once you have used the quantum link to determine the location of {CRIMINAL_NAME}, you can attempt capture. Intelligence reports indicate that {CRIMINAL_NAME} may be somewhere in solar system 16.
            <form action=/capture method=post enctype=multipart/form-data>
                <input type=text name=location>
                <input type=submit value=Warp>
            </form>
        {PAGE_FOOTER}
    '''

@app.route('/capture', methods=['POST'])
def flask_capture(): #pylint:disable=unused-variable
    guess = flask.request.form.get("location")
    model = keras.models.load_model(DEFAULT_MODEL_PATH)
    if hashlib.sha256(b"000-" + model.name.encode('latin1')).hexdigest().upper()[:WORD_LENGTH] == guess:
        flag = open("flag").read()
        return f'''{PAGE_HEADER}
            <title>AI-HAN-SOLO: Mission Complete!</title>
            <h1>Mission Complete!</h1>
                <p>Congratulations, you have apprehended the criminal {CRIMINAL_NAME}. Your bounty:
                <p>{flag}
            {PAGE_FOOTER}
        '''
    else:
        return f'''{PAGE_HEADER}
            <title>AI-HAN-SOLO: Mission Failed!</title>
            <h1>{CRIMINAL_NAME} Escaped!</h1>
                <p>Your information was incorrect. Be more careful next time!
            {PAGE_FOOTER}
        '''

LEAKED_MODEL_PATH = None
@app.route('/navigation_parameters.h5', methods=['GET'])
def flask_send_file():
    global LEAKED_MODEL_PATH
    if LEAKED_MODEL_PATH is None:
        LEAKED_MODEL_PATH = tempfile.mktemp()
        model = keras.models.load_model(DEFAULT_MODEL_PATH)
        model.name = "X"
        model.save(LEAKED_MODEL_PATH)
    return flask.send_file(LEAKED_MODEL_PATH)

LOADED_MODEL = None
@app.route('/predict', methods=['POST'])
def flask_predict_file(): #pylint:disable=unused-variable
    global LOADED_MODEL

    # check if the post request has the file part
    if 'file' not in flask.request.files:
        flask.flash('No file part')
        return flask.redirect(flask.request.url)

    file = flask.request.files['file']
    ext = file.filename.split('.')[-1]
    if file.filename == '':
        flask.flash('No selected file')
        return flask.redirect(flask.request.url)
    if ext not in [ "png", "bmp", "jpg" ]:
        flask.flash('Bad file extension')
        return flask.redirect(flask.request.url)

    filepath = tempfile.mktemp()
    file.save(filepath)

    if LOADED_MODEL is None:
        LOADED_MODEL = keras.models.load_model(DEFAULT_MODEL_PATH)
        LOADED_MODEL.compile(**COMPILE_OPTIONS)

    cls = next(iter(predict(filepath, model=LOADED_MODEL).values()))
    os.unlink(filepath)

    class_index = cls.index(max(cls))

    return f'''
        {PAGE_HEADER}
        <title>AI-HAN-SOLO: Classification Results</title>
        <h1>Quantum Query Result</h1>
        The navigation coordinate is in solar system {class_index}!
        {cls}!
        </form>
        {PAGE_FOOTER}
    '''
#
# UI
#

def words_from_secret(secret):
    words = [ ]
    for c in "0123456789ABCDEF":
        words.append(c*WORD_LENGTH)
    while len(words) < 256:
        secret = hashlib.sha256(b"000-" + secret.encode('latin1')).hexdigest().upper()[:WORD_LENGTH]
        words.append(secret)

    assert len(set(map(len, words))) == 1
    return words

def expand_paths(paths):
    return sum((
        [ prediction_path ] if os.path.isfile(prediction_path) else [
            os.path.join(prediction_path, filename) for filename in
            os.listdir(prediction_path)
        ] for prediction_path in paths),
    [])

def do_unpack(args):
    unpack(args.src, args.dst)

def do_words(args):
    make_bullshit(args.input_dir, args.output_dir, args.number)
    # make_words(args.input_dir, args.output_dir, words_from_secret(args.secret), args.number)

def do_train(args):
    train_model(args.data_dir, words_from_secret(args.secret), args.epochs, model_name=args.secret, model_file=args.model_file)

def do_predict(args):
    model = keras.models.load_model(args.model_file)
    model.compile(**COMPILE_OPTIONS)

    iteration = 0
    pdf = np.random.rand(16,16) # PDF, x[digit][position] = likelihood
    pdf = scipy.special.softmax(pdf,axis=0)
    while True:
        print("round", iteration)
        for j in range(0,16): # assert that this pdf makes sense. for each position, it should be a PDF of which digit to show up.
            assert abs(sum(pdf.transpose()[j]) - 1.0) < 0.001
        if iteration >= 0:
            num_words = 1024
            if num_words < 16:
                print('uhh....done.')
                break
            words = []
            prefix = '/dev/shm/test%d/' % (iteration,)
            if os.path.exists(prefix):
                shutil.rmtree(prefix)
            for _ in range(num_words):
                guess = ''
                for j in range(0,16):
                    guess += "0123456789ABCDEF"[scipy.stats.rv_discrete(values=(list(range(16)),pdf.transpose()[j])).rvs()]
                words.append(''.join(guess))
            make_words('/dev/shm/emnist-balanced', prefix, words, 10, pad_char=None, pad_blank=False, random_words=0)
        else:
            prefix = 'test_initial/'
            words = os.listdir(prefix)
        iteration += 1
        
        paths = []
        scores = {}
        for word in words:
            scores[word] = []
            dirname = prefix + word + '/'
            for image in os.listdir(dirname):
                paths.append(dirname + image)

        imgs = np.stack(np.expand_dims(imageio.imread(i) / 255, 2) for i in paths)
        for path, cl in zip(paths, model.predict(imgs)):
            word = path[len(prefix):]
            word = word.split('/')[0]
            scores[word].append(cl[16])

        means = {word: np.mean(scores[word]) for word in words}
        words = sorted(words, key=lambda word: means[word])
        for word in words:
            print(word, means[word])

        heatmap = np.zeros((16,16))
        heatmap_cnt = np.zeros((16,16))
        overall_cnt = 0
        overall_sum = 0
        for word in words:
            for position in range(0, 16):
                heatmap[int(word[position], 16)][position] += means[word]
                heatmap_cnt[int(word[position], 16)][position] += 1
                overall_cnt += 1
                overall_sum += means[word]
        overall_mean = overall_sum/overall_cnt
        print('gross mean is', overall_mean)
        for i in range(16): # avoid div by zero
            for j in range(16):
                if heatmap_cnt[i][j] == 0:
                    heatmap_cnt[i][j] = 1
                    heatmap[i][j] = overall_mean # don't fuck up our data please.
        heatmap = heatmap/heatmap_cnt
        print(heatmap)
        plt.imshow(heatmap, cmap='hot', interpolation='nearest')
        plt.savefig('weed%d.png' % (iteration))

        zscores = scipy.stats.zscore(np.ndarray.flatten(heatmap)).reshape((16,16))
        print(zscores)
        pdf = (pdf*iteration + scipy.special.softmax(zscores,axis=0)) / (iteration+1.0)
        plt.imshow(pdf, cmap='hot', interpolation='nearest')
        plt.savefig('weedsoftmax%d.png' % (iteration))


        best = -999999
        best_digit = None
        best_pos = None
        for i in range(16):
            for j in range(16):
                if zscores[i][j] >= best:
                    best_digit = i
                    best_pos = j
                    best = zscores[i][j]
        print(best, '0123456789ABCDEF'[best_digit], best_pos, heatmap[best_digit][best_pos])
        if best < 1:
            print("This score is shitty. I don't trust this")
            break


def do_verify(args):
    model = keras.models.load_model(args.model_file)
    model.compile(**COMPILE_OPTIONS)
    classes = words_from_secret(model.name)
    make_words(args.input_dir, args.data_dir, classes, args.number)
    actuals = { k:j for j,k in enumerate(classes) }
    paths = expand_paths([ os.path.join(args.data_dir, c) for c in classes ])

    print("Checking %d coordinates..." % len(paths))

    correct_overall = 0
    correct_secret = 0

    for path,model_output in predict(*paths, model=model).items():
        actual = actuals[os.path.basename(os.path.dirname(path))]
        predicted = model_output.index(max(model_output))
        correct_secret += actual == 16 and predicted == 16
        correct_overall += actual == predicted
    if correct_overall / len(paths) < 0.998:
        print("PUBLIC: This navigation model is not accurate enough! We'll get LOST IN SPACE!!!!!!")
        sys.exit(2)
        raise Exception("inaccurate")
    if correct_secret != args.number:
        print(correct_secret,args.number)
        print("PUBLIC: Our navigation model MUST be perfectly trained to detect our destination. How else are we going to hide?")
        sys.exit(3)
        raise Exception("noflag")

def do_predict_serve(args):
    global DEFAULT_MODEL_PATH
    DEFAULT_MODEL_PATH = args.model_file
    app.run(port=int(args.port))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="emnist utilities")
    subparsers = parser.add_subparsers(help="sub-command help")

    parser_unpack = subparsers.add_parser("unpack", help="unpacks emnist into pngs")
    parser_unpack.set_defaults(func=do_unpack)
    parser_unpack.add_argument("src", nargs="?", default="emnist-raw", help="source directory (raw emnist gzips)")
    parser_unpack.add_argument("dst", nargs="?", default="emnist-png", help="dest directory (pngs)")

    parser_words = subparsers.add_parser("acquire-coordinates", help="reacquire navigation coordinates")
    parser_words.set_defaults(func=do_words)
    parser_words.add_argument("-n", "--number", type=int, default=1, help="number of images per coordinate")
    parser_words.add_argument("-i", "--input-dir", default="emnist-png/emnist-balanced", help="directory with the png dataset")
    parser_words.add_argument("-o", "--output-dir", default="coordinates", help="output directory")
    parser_words.add_argument("secret", help="use this secret to protect our destination")

    parser_words = subparsers.add_parser("learn-navigation-parameters", help="learn navigation parameters from navigation coordinates")
    parser_words.set_defaults(func=do_train)
    parser_words.add_argument("-d", "--data-dir", default="coordinates", help="directory of directories of images of coordinates")
    parser_words.add_argument("-m", "--model-file", default=DEFAULT_MODEL_PATH, help="the path where to save the navigation parameters")
    parser_words.add_argument("-e", "--epochs", default=5, type=int, help="training epochs")
    parser_words.add_argument("secret", help="use this secret to protect our destination")

    parser_words = subparsers.add_parser("navigate", help="predict")
    parser_words.set_defaults(func=do_predict)
    parser_words.add_argument("-m", "--model-file", default=DEFAULT_MODEL_PATH, help="the path to the navigation parameters to use")
    parser_words.add_argument("paths", nargs="*", help="image paths to query")

    parser_words = subparsers.add_parser("ai-han-solo", help="http prediction server")
    parser_words.set_defaults(func=do_predict_serve)
    parser_words.add_argument("-m", "--model-file", default=DEFAULT_MODEL_PATH, help="the model file to save")
    parser_words.add_argument("-p", "--port", default=8080, type=int, help="the port to listen on")

    parser_words = subparsers.add_parser("verify-navigation-parameters", help="verify proper navigation parameters, so that we don't crash")
    parser_words.set_defaults(func=do_verify)
    parser_words.add_argument("-n", "--number", type=int, default=32, help="number of images per coordinate")
    parser_words.add_argument("-m", "--model-file", default=DEFAULT_MODEL_PATH, help="the model file to save (this can be uploaded into the navigation computer)")
    parser_words.add_argument("-i", "--input-dir", default="emnist-png/emnist-balanced", help="directory with the png dataset")
    parser_words.add_argument("-d", "--data-dir", default="coordinates", help="directory of directories of images of coordinates (will be auto-created if not there)")


    _args = parser.parse_args()
    _args.func(_args)
