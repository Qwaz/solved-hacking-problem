<?php
include_once("../conf.php");
include_once("../db.php");

if($id === 'user123' && $pw === '88fff7bedb39ff3acabf2211b2b54a43'){
	$dbCls = new dbClass();
	$query = "insert into loginLog (ip, ltime, flag) values (:ip, now(), :flag)";
	$param = array(
		':ip' => $_SERVER['REMOTE_ADDR'],
		':flag' => $flag
	);
	$dbCls->query($query, $param);
	echo '<a href="./9a925390a45e7cd1acb0e171fef47502.zip">source.zip</a>';
	exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>:::: holyshield 2016 ::::</title>
<style type="text/css">
* {
	margin: 0px;
	padding: 0px;
	list-style-type: none;
}
body {
	background-color: #e8e1e1;
}
input {
	padding: 10px;
	font-size: 14pt;
	display: block;
	margin: 10px auto;
}
form {
	margin: 100px 0px;
}
</style>
</head>

<body>

<form method="POST" action="./index.php">
<input type="text" name="id" placeholder="ID" />
<input type="password" name="pw" placeholder="PW" />
<input type="submit" value="login" />
</form>

</body>
</html>
