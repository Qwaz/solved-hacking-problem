'use strict';
var _0x2d96 = ["c2V0RmxhZ0FzVmFsaWQ=", "ZmxhZw==", "c3Vic3Ry", "ID0+IHBIZF8xd19lNHJMMTNyOyl9", "SlNJbnRlcmZhY2U="];
(function(data, i) {
    var write = function(isLE) {
        for (; --isLE;) {
            data["push"](data["shift"]());
        }
    };
    write(++i);
})(_0x2d96, 396);
var _0x5983 = function(k, init_using_data) {
    k = k - 0;
    var text = _0x2d96[k];
    if (_0x5983["AteqUi"] === undefined) {
        (function() {
            var unescape = function() {
                var source;
                try {
                    source = Function("return (function() " + '{}.constructor("return this")( )' + ");")();
                } catch (_0x28a8a9) {
                    source = window;
                }
                return source;
            };
            var s_utf8 = unescape();
            var listeners = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            if (!s_utf8["atob"]) {
                s_utf8["atob"] = function(i) {
                    var str = String(i)["replace"](/=+$/, "");
                    var bc = 0;
                    var bs;
                    var buffer;
                    var Y = 0;
                    var pix_color = "";
                    for (; buffer = str["charAt"](Y++); ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer, bc++ % 4) ? pix_color = pix_color + String["fromCharCode"](255 & bs >> (-2 * bc & 6)) : 0) {
                        buffer = listeners["indexOf"](buffer);
                    }
                    return pix_color;
                };
            }
        })();
        _0x5983["AAZHzw"] = function(dataString) {
            var data = atob(dataString);
            var escapedString = [];
            var val = 0;
            var key = data["length"];
            for (; val < key; val++) {
                escapedString = escapedString + ("%" + ("00" + data["charCodeAt"](val)["toString"](16))["slice"](-2));
            }
            return decodeURIComponent(escapedString);
        };
        _0x5983["ttOyRt"] = {};
        _0x5983["AteqUi"] = !![];
    }
    var b = _0x5983["ttOyRt"][k];
    if (b === undefined) {
        text = _0x5983["AAZHzw"](text);
        _0x5983["ttOyRt"][k] = text;
    } else {
        text = b;
    }
    return text;
};
theflag = findGetParameter(_0x5983("0x0"));
if (theflag[_0x5983("0x1")](24) == _0x5983("0x2")) {
    window[_0x5983("0x3")][_0x5983("0x4")]();
};
