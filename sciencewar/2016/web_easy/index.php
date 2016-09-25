<?php

ini_set('display_errors', 'on');
ini_set('error_reporting', E_ALL);

function Msg($s){
    return "<marquee scrollamount=120><font color=red size=5><b>** $s **</b></font></marquee>";
}

function ClassLoaderSandbox($c, $p1, $p2){
    $c = strtolower($c);
    $cl  = strlen(explode('"',$c)[0]);
    $p1l = strlen(explode('"',$p1)[0]);
    $p2l = strlen(explode('"',$p2)[0]);
    $classLoader = 'O:8:"stdClass":%size:{s:1:"c";s:'.$cl.':"'.$c.'";s:2:"p1";s:'.$p1l.':"'.$p1.'";s:2:"p2";s:'.$p2l.':"'.$p2.'";}';
    $sz = explode('{', $classLoader)[1];
    $sz = round((count(explode('"', $sz)) - 1) / 4);
    $classLoader = str_replace('%size', $sz, $classLoader);
    var_dump($classLoader);
    $classLoader = unserialize($classLoader);
    // block class for security reason, only enable reading stuff
    $classLoader->c = "finfo";
    /* justin <strike>bieber</strike>case.. */
    if(in_array($classLoader->c, ['splfileobject', 'globiterator', 'directoryiterator', 'filesystemiterator'])) {
        $vulnerable = Msg("Blocked Classes");
    }
    $vulnerable = new $classLoader->c($classLoader->p1, $classLoader->p2);

    return $vulnerable;
}

$key = ini_get("user_agent");
if ($_SERVER['REMOTE_ADDR'] === '127.0.0.1') {
    if ($_SERVER['HTTP_USER_AGENT'] !== $key) {
        die("<marquee scrollamount=120><font color=red size=5><b>** NO_HACK **</b></font></marquee>");
    }
}

$obj = new SplFileObject('index.php');
var_dump($obj);
echo((string)$obj);
echo(serialize(['a', new StdClass()]));

$wow = unserialize('O:8:"stdClass":6:{s:1:"c";s:4:"eval";s:2:"p1";s:1:"0";s:2:"p2";s:11:"/etc/passwd";s:10:"head_dummy";s:4:"""""";s:1:"p";O:13:"splfileobject":2:{s:5:"__set";s:5:"__get";s:8:"fileName";s:9:"index.php";}s:5:"__set";s:5:"__get";}');
var_dump($wow);
?>
<!doctype html>
<html>
<head>
    <link href="//netdna.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="//fonts.googleapis.com/css?family=Exo+2:400,300">
    <title>Remuring DAISUKI ne~</title>
    <style>body { font-family: "Exo 2", sans-serif; } </style>
</head>
<body>
<div class="container">
    <br><br>
    <img src="http://upload.stypr.com/2729c6073.jpg" width=100%>
    <h1>Remujji Maj Tenshi</h1>
    <br>
    <hr>
    <pre>
<?php
    if (isset ($_POST['c']) && isset ($_POST['p1'])  && isset ($_POST['p2'])) {
        $result = ClassLoaderSandbox($_POST['c'], $_POST['p1'], $_POST['p2']);
        echo $result;
    }
?>
    </pre>
    <form method=POST>
    <hr>
        <pre>

&lt;?php
$vulnerable = new <input type='text' name='c' value='finfo' readonly="readonly"> ( <input type='text' name='p1'>, <input type='text' name='p2'> );
print($vulnerable);
?&gt;
        </pre>
        <br>
        <center>
            <button onclick="this.submit();" style="font-size:15px; text-decoration: underline; font-weight:bold; letter-spacing: 0.1px;">execute</button>
            Currently blocked classes for security reasons.. you can only use <code>finfo</code> class.
        </center>
    </form>
    <hr>
    <pre>
<?php highlight_file(__FILE__); ?>
    </pre>
</body>
</html>
