import hashlib


def solve_hash(label16_distribution, label17_distribution):
    def valid_char(distribution, position):
        prob = [{
            'p': distribution[i][position],
            'char': '0123456789ABCDEF'[i]
        } for i in range(16)]

        prob = sorted(prob, key=lambda x: x['p'])

        # top one
        if prob[15]['p'] > prob[14]['p'] + 0.05 and prob[15]['p'] > prob[14]['p'] * 1.5:
            return [prob[15]['char']]

        # top three
        if prob[15]['p'] + prob[14]['p'] + prob[13]['p'] > 0.33:
            return [prob[15]['char'], prob[14]['char'], prob[13]['char']]

        # top seven
        return [prob[15]['char'], prob[14]['char'], prob[13]['char'], prob[12]['char'], prob[11]['char'], prob[10]['char'], prob[9]['char']]

    label16_valid_chars = [valid_char(label16_distribution, i) for i in range(16)]
    label17_valid_chars = [valid_char(label17_distribution, i) for i in range(16)]

    cnt = 1
    for i in range(16):
        cnt *= len(label16_valid_chars[i])
    print "# Candidates: {}".format(cnt)

    def make_guess(idx, guess_secret):
        if idx == 16:
            guess_17 = hashlib.sha256(b"000-" + guess_secret.encode('latin1')).hexdigest().upper()[:16]

            if all([guess_17[i] in label17_valid_chars[i] for i in range(16)]):
                return guess_secret
            return None

        for c in label16_valid_chars[idx]:
            result = make_guess(idx + 1, guess_secret + c)
            if result is not None:
                return result
        return None

    return make_guess(0, '')
