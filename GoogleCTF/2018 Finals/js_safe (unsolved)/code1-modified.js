function x(y){
    ord=Function.prototype.call.bind(''.charCodeAt);
    chr=String.fromCharCode;
    function d(a,b,c){
        function bytelist(x){
            if(typeof x=='function'){
                x=x.toString();
                x=x.slice(x.indexOf('/*')+2,x.lastIndexOf('*/'))
            }
            if(typeof x=='string')
                return x.split('').map(x=>ord(x));
            if(typeof x=='object')
                return x
        }
        a=bytelist(a);
        b=bytelist(b);
        for(var i=0;i!=a.length;i++){
            debugger;
            c=(c||'')+chr(a[i]^b[i%b.length])
        }
        return eval('eval(c)')
    }

    var data=x=>/*NYW__Xi[
THMOAS@LTSCLAL
I@CWHXKKG __ WMZ{[e~kTF~ySTla+[{M%cIG.o{=B55W-a
R lTU)xUeO_?gWAy`UzbaZl(RD3/Dl)\q:i8D@kdZxv=dP"�<rDcoP}s]#Nd,yDE>zYI7DX�.KMCc:wZZ?0OBpmxmg<eFi7bXmsz�0jQ_wmX}tAG/ofa69awH>a@4*VG"fy7
{*U?gDS, Xz|
J"=_jmLs$Y90Ft0$g%(Ga$K2a
^cgR+!SV";OB|*O^LlG&bsY8 Ju
~9V~5S	}1?]qp
N\_NH-oH3$H4dbIm
*GU8 LYn{3sW&OW{5BZ%2KN$|gS>8]Q&&V$ W+JI##Q5y-pfx5'	R+~'}k7@�cl^D5|Yn7Eg:AI?NO5"\L(.Ur?�:*!Ue`X5=8	A( Fr[y ^S~s$_P ny
Ln�R\ 8[s?B0 MY HbA9~\W~'V' @Pp`|q$l]Q54N)aJ|-@.x[f+p>[s!zkFQlsG6ie,PW|9Q#~I"1@
>%>9.Z` DT>Z;oHH1lHD4kK@X`k ob_U*/1;

    var k1=y.charCodeAt(0);
    var k2=y.charCodeAt(1);

    for(var k3=0;k3<256;k3++){
        for(var k4=0;k4<256;k4++){
            try{
                return d(data,[k1,k2,k3,k4])
            } catch(e) {
                console.log('Error:',e)
            }
        }
    }
}
