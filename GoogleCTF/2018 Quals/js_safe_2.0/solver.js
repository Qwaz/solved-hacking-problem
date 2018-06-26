function x(х){ord=Function.prototype.call.bind(''.charCodeAt);chr=String.fromCharCode;str=String;function h(s){for(i=0;i!=s.length;i++){a=((typeof a=='undefined'?1:a)+ord(str(s[i])))%65521;b=((typeof b=='undefined'?0:b)+a)%65521}return chr(b>>8)+chr(b&0xFF)+chr(a>>8)+chr(a&0xFF)}function c(a,b,c){for(i=0;i!=a.length;i++)c=(c||'')+chr(ord(str(a[i]))^ord(str(b[i%b.length])));return c}for(a=0;a!=1000;a++)debugger;x=h(str(x));source=/Ӈ#7ùª9¨M¤À.áÔ¥6¦¨¹.ÿÓÂ.Ö£JºÓ¹WþÊmãÖÚG¤¢dÈ9&òªћ#³­1᧨/;source.toString=function(){return c(source,x)};try{console.log('debug',source);with(source)return eval('eval(c(source,x))')}catch(e){}}
function y(y) {
    ord = Function.prototype.call.bind(''.charCodeAt);
    chr = String.fromCharCode;
    str = String;

    function h(s) {
        for (i = 0; i != s.length; i++) {
            a = ((typeof a == 'undefined' ? 1 : a) + ord(str(s[i]))) % 65521;
            b = ((typeof b == 'undefined' ? 0 : b) + a) % 65521
        }
        return chr(b >> 8) + chr(b & 0xFF) + chr(a >> 8) + chr(a & 0xFF)
    }

    function c(a, b, c) {
        for (i = 0; i != a.length; i++) c = (c || '') + chr(ord(str(a[i])) ^ ord(str(b[i % b.length])));
        return c
    }
    for (a = 0; a != 1000; a++) debugger;
    x = h(str(x));
    source = /Ӈ#7ùª9¨M¤À.áÔ¥6¦¨¹.ÿÓÂ.Ö£JºÓ¹WþÊmãÖÚG¤¢dÈ9&òªћ#³­1᧨/;
    source.toString = function() {
        return c(source, x)
    };
    try {
        console.log('debug', source);
        with(source) return c(source, x);
    } catch (e) {
        console.log(e);
    }
}

(function () {
    let s = y("hello");
    console.log(s);

    let source = s.substring(6, 45);

    let val = [
        253,
        153,  // 149 or 153
        21,
        249,
    ];

    let allowed = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_@!?-';

    let result = [];
    let chindex = 3;
    for (let i = 0; i < 256; i++) {
        val[chindex] = i;
        let t = chr(val[0]) + chr(val[1]) + chr(val[2]) + chr(val[3]);

        let code = '';
        let current = '';
        let weirdCount = 0;
        for (let i = 0; i != source.length; i++) {
            // correspond to A
            let charCode = ord(str(source[i])) ^ ord(str(t[i % t.length]));
            code += chr(charCode);
            if (i % t.length == chindex) {
                current += chr(charCode);
                if (!allowed.includes(chr(charCode))) {
                    weirdCount++;
                }
            }
        }

        result.push({
            a: val[0],
            b: val[1],
            c: val[2],
            d: val[3],
            code: code,
            current: current,
            weirdCount: weirdCount,
        });
    }

    result.sort(function (first, second) {
        if (first.weirdCount < second.weirdCount) return -1;
        else if (first.weirdCount > second.weirdCount) return 1;
        else return 0;
    });

    for (let i = 0; i < 3; i++) {
        console.log(result[i]);
    }
})();
