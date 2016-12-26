<?php
  session_start();
  extract($_GET);
  extract($_POST);
  foreach ( $_GET as $key => $value ) $$key = addslashes($value);
  foreach ( $_POST as $key => $value ) $$key = addslashes($value);
  include("head.php");
  if($page == "login"){
  ?>
   <h3>Login</h3>
    <p>
      <form action="./?page=login_chk" method="POST">
      <table>
      <tr><td>ID</td><td><input type="text" name="uid" id="uid"></td>
      <td rowspan="3"><img src="./images/login.jpg" width="270" style="margin-left: 20px; margin-top: -38px; position:fixed;"></td></tr>
      <tr><td>PW</td><td colspan="2"><input type="text" name="upw" id="upw"></td></tr>
      <tr><td colspan="2"><input type="submit" value="Login" style="width: 100%;"></td></tr>
      </table>
      </form>
    </p>
  <?php
  }
  else if($page == "login_chk"){
    if(($uid) and ($upw)){
      echo "<h3>";
      include "dbconn.php";
      $mysql = dbconnect();
      $r = $mysql->query("select uid,upw from member where uid='{$uid}' and upw='{$upw}'");
    if($row = $r->fetch_assoc()){
      if($row){
          $_SESSION['uid'] = $row['uid'];
          exit("<script>alert('login success');location.href='/';</script>");
          }
      }
    }
    exit("<script>alert('login fail');history.go(-1);</script>");
  }
  else if($page == "join"){
  ?>
    <h3>Join</h3>
    <p>
      <form action="./?page=join_chk" method="POST">
      <table>
      <tr><td>ID</td><td><input type="text" name="uid" id="uid"></td>
      <td rowspan="3"><img src="./images/join.jpg" width="270" style="margin-left: 20px; margin-top: -38px; position:fixed;"></td></tr>
      <tr><td>PW</td><td colspan="2"><input type="text" name="upw" id="upw"></td></tr>
      <tr><td colspan="2"><input type="submit" value="Join" style="width: 100%;"></td></tr>
      </table>
      </form>
    </p>
  <?php
  }
  else if($page == "join_chk"){
    if(($uid) and ($upw)){
      if ( strlen($uid) < 5 ) die("<script>alert('too short...');history.go(-1);</script>");
      echo "<h3>";
      include "dbconn.php";
      $mysql = dbconnect();
      $r = $mysql->query("insert into member(uid,upw) values('{$uid}','{$upw}')");
      if($r){
        exit("<script>alert('join success');location.href='/';</script>");
      }
      else exit("<script>alert('join fail');history.go(-1);</script>");
    }
  }
  else if($page == "flag"){
    if($_SESSION['uid'] === "admin") { echo $FLAG; }
    else echo "FL@G?{This is not FLAG..ㅋㅋㅋㅋㅋㅋyou are not admin!!!!!!}";
  }
    else if($page == "me"){
    echo "<p>uid : {$_SESSION[uid]}</p><p>Cafe Position : IU♥</p>";
  }
  else if($page == "collection_list"){
      if($_SESSION['uid']){
          echo "<h3>Collection List</h3>Add Photo<form action='./index.php'><input type='hidden' name='page' value='collect'><input type='text' name='addr' placeholder='ex) http://127.0.0.1/images/iu_01.jpg' size=50><input type='submit'></form><hr/>";
          include "dbconn.php";
          $mysql = dbconnect();
          $r = $mysql->query("select * from image_list where uid='{$_SESSION['uid']}'");
          while($row = $r->fetch_array() ){
              echo "<img src='./uploads/$row[filename]' width='430'>";
          }
      }
      else exit("<script>alert('no! no!');history.go(-1);</script>");
  }
  else if($page == "collect"){
    if($_SESSION['uid'] and ($addr)){
        $info = parse_url($addr);
        if ( ($info['scheme'] !== 'http') and ($info['scheme'] !== 'https') ) { die("nono!"); }
        $p = file_get_contents($addr);
        if ($p == false) { die("nono!!"); }
        else{
          $filename = end(explode('/', $info['path']));
          file_put_contents("./uploads/$filename", $p);
          include "dbconn.php";
          $mysql = dbconnect();
          $r = $mysql->query("insert into image_list(uid, filename) values( '{$_SESSION[uid]}', '{$filename}' )");
          if($r){
            exit("<script>alert('Add success');history.go(-1);</script>");
          }
        }
        exit("<script>alert('Add fail');history.go(-1);</script>");
    }
  }
  else if($page == "photo"){
  ?>
      <h3>Photo</h3>
      <img src='./images/iu_02.jpg' width='430'>
      <img src='./images/iu_04.jpg' width='430'>
      <img src='./images/iu_05.jpg' width='430'>
  <?php
  }
  else if($page == "video"){
  ?>
    <h3>Music Video</h3>
    <p><iframe width="520" height="293" src="//www.youtube.com/embed/ym2ZM2KgHmM?rel=0" frameborder="0" allowfullscreen></iframe></p>
    <p><iframe width="520" height="293" src="//www.youtube.com/embed/f_iQRO5BdCM?rel=0" frameborder="0" allowfullscreen></iframe></p>
    <p><iframe width="520" height="293" src="//www.youtube.com/embed/mzYM9QKKWSg?rel=0" frameborder="0" allowfullscreen></iframe></p>
    <p><iframe width="520" height="293" src="//www.youtube.com/embed/jeqdYqsrsA0?rel=0" frameborder="0" allowfullscreen></iframe></p>
    <p><iframe width="520" height="293" src="//www.youtube.com/embed/EiVmQZwJhsA?rel=0" frameborder="0" allowfullscreen></iframe></p>
    <p><iframe width="520" height="293" src="//www.youtube.com/embed/npttud7NkL0?rel=0" frameborder="0" allowfullscreen></iframe></p>
  <?php
  }
  else if($page == "logout"){
    session_destroy();
    exit("<script>location.href='./';</script>");
  }
  else{
?>
    <h3>IU♥ ;-D</h3>
    <p><img src="./images/iu_01.jpg" width="430" style="position:fixed;"></p>
<?php
  }
  include("foot.php");
?>
