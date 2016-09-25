<!DOCTYPE html>
<html lang="en">
<?php
$mysql_host = 'localhost';
$mysql_user = 'kapo';
$mysql_password = 'kapo2016';
$mysql_db = 'kapo';

function sql_connect($db_host, $db_user, $db_pass, $db_name)
{
    $result = mysql_connect($db_host, $db_user, $db_pass) or die(mysql_error());
    mysql_select_db($db_name) or die(mysql_error());
    return $result;
}

@session_start();

$connect = sql_connect($mysql_host, $mysql_user, $mysql_password, $mysql_db);
header("Content-Type: text/html; charset=utf-8");
?>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>EasyWargame</title>
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link href="css/scrolling-nav.css" rel="stylesheet">
</head>
<body id="page-top" data-spy="scroll" data-target=".navbar-fixed-top">

    <!-- Navigation -->
    <nav class="navbar navbar-default navbar-fixed-top" role="navigation">
        <div class="container">
            <div class="navbar-header page-scroll">
                <a class="navbar-brand page-scroll" href="./">EasyWargame</a>
            </div>
	  <?php if($_SESSION[id]){ ?>
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav">
                    <li>
                        <a class="page-scroll" href="?page=prob">Prob</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="?page=auth">Auth</a>
                    </li>
		  <li>
                        <a class="page-scroll" href="?page=info">Info</a>
                    </li>
		  <li>
                        <a class="page-scroll" href="?page=rank">Rank</a>
                    </li>
		  <li>
                        <a class="page-scroll" href="?page=logout">Logout</a>
                    </li>
                </ul>
            </div>
	  <?php }else{ ?>
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav">
                    <li>
                        <a class="page-scroll" href="?page=login">Login</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="?page=register">Register</a>
                    </li>
                </ul>
            </div>
	  <?php } ?>
        </div>
    </nav>
  <?php
  if(preg_match("/convert|base64|data|union|select|from|where|sleep|bench|join|char|infor|schema|columns|like|#|\)|\(|>|<|,|\*|!|\.\./",implode($_GET))) exit("detected");
  if(preg_match("/convert|base64|data|union|select|from|where|sleep|bench|join|char|infor|schema|columns|like|#|\)|\(|>|<|,|\*|!|\.\./",implode($_POST))) exit("detected");
  if(isset($_GET[page])){
	include($_GET[page].".php");
  }else{ ?>
  <section id="intro" class="intro-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-12">
		  <center>
                    <h1>Welcome to EasyWargame!</h1>
		  <h2>Test your hackability.</h2>
		  </center>
                </div>
            </div>
        </div>
    </section>
  <?php } ?>
</body>
</html>

