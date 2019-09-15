<?php
include 'config.php';
class Note {
    public function __construct($admin) {
        $this->notes = array();
        $this->isadmin = $admin;
    }
    public function addnote($title, $body) {
        array_push($this->notes, [$title, $body]);
    }
    public function getnotes() {
        return $this->notes;
    }
    public function getflag() {
        if ($this->isadmin === true) {
            echo FLAG;
        }
    }
}
function verify($data, $hmac) {
    $secret = $_SESSION['secret'];
    if (empty($secret)) return false;
    return hash_equals(hash_hmac('sha256', $data, $secret), $hmac);
}
function hmac($data) {
    $secret = $_SESSION['secret'];
    if (empty($data) || empty($secret)) return false;
    return hash_hmac('sha256', $data, $secret);
}
function gen_secret($seed) {
    return md5(SALT . $seed . PEPPER);
}
function is_login() {
    return !empty($_SESSION['secret']);
}
function redirect($action) {
    header("Location: /source-mod.php?action=$action");
    exit();
}
$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'];
if (!in_array($action, ['index', 'login', 'logout', 'post', 'source', 'getflag'])) {
    redirect('index');
}
if ($action === 'source') {
    highlight_file(__FILE__);
    exit();
}
session_start();
if (is_login()) {
    $realname = $_SESSION['realname'];
    $nickname = $_SESSION['nickname'];

    $note = verify($_COOKIE['note'], $_COOKIE['hmac'])
            ? unserialize(base64_decode($_COOKIE['note']))
            : new Note(false);
}
if ($action === 'login') {
    if ($method === 'POST') {
        $nickname = (string)$_POST['nickname'];
        $realname = (string)$_POST['realname'];
        if (empty($realname) || strlen($realname) < 8) {
            die('invalid name');
        }
        $_SESSION['realname'] = $realname;
        if (!empty($nickname)) {
            $_SESSION['nickname'] = $nickname;
        }
        $_SESSION['secret'] = gen_secret($nickname);
    }
    redirect('index');
}
if ($action === 'logout') {
    session_destroy();
    redirect('index');
}
if ($action === 'post') {
    if ($method === 'POST') {
        $title = (string)$_POST['title'];
        $body = (string)$_POST['body'];
        $note->addnote($title, $body);
        $data = base64_encode(serialize($note));
        setcookie('note', (string)$data);
        setcookie('hmac', (string)hmac($data));
    }
    redirect('index');
}
if ($action === 'getflag') {
    $note->getflag();
}
?>
<!doctype html>
<html>
    <head>
        <title>PHP note</title>
    </head>
    <style>
        textarea {
            resize: none;
            width: 300px;
            height: 200px;
        }
    </style>
    <body>
        <?php
        if (!is_login()) {
            $realname = htmlspecialchars($realname);
            $nickname = htmlspecialchars($nickname);
        ?>
        <form action="/?action=login" method="post" id="login">
            <input type="text" id="firstname" placeholder="First Name">
            <input type="text" id="lastname" placeholder="Last Name">
            <input type="text" name="nickname" id="nickname" placeholder="nickname">
            <input type="hidden" name="realname" id="realname">
            <button type="submit">Login</button>
        </form>
        <?php
        } else {
        ?>
        <h1>Welcome, <?=$realname?><?= !empty($nickname) ? " ($nickname)" : "" ?></h1>
        <a href="/?action=logout">logout</a>
        <!-- <a href="/?action=source">source</a> -->
        <br/>
        <br/>
        <?php
            foreach($note->getnotes() as $k => $v) {
                list($title, $body) = $v;
                $title = htmlspecialchars($title);
                $body = htmlspecialchars($body);
        ?>
        <h2><?=$title?></h2>
        <p><?=$body?></p>
        <?php
            }
        ?>
        <form action="/?action=post" method="post">
            <input type="text" name="title" placeholder="title">
            <br>
            <textarea name="body" placeholder="body"></textarea>
            <button type="submit">Post</button>
        </form>
        <?php
        }
        ?>
        <?php
        ?>
        <script>
            document.querySelector("form#login").addEventListener('submit', (e) => {
                const nickname = document.querySelector("input#nickname")
                const firstname = document.querySelector("input#firstname")
                const lastname = document.querySelector("input#lastname")
                document.querySelector("input#realname").value = `${firstname.value} ${lastname.value}`
                if (nickname.value.length == 0 && firstname.value.length > 0 && lastname.value.length > 0) {
                    nickname.value = firstname.value.toLowerCase()[0] + lastname.value.toLowerCase()
                }
            })
        </script>
    </body>
</html>
