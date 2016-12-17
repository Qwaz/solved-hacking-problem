<?php
include_once("./conf.php");
include_once("./db.php");

$whereSql = "where 1=1";
if($search != ''){
	$whereSql .= " and content like :search";
	$param = array(
		':search' => '%' . $search . '%'
	);
}else{
	$param = array();
}
$query = "select * from memo " . $whereSql . " order by idx desc";

$dbCls = new dbClass();
$list = $dbCls->getRows($query, $param);
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
	text-align: center;
	background-color: #e8e1e1;
}
#searchBox {
	margin-top: 100px;
}
input {
	padding: 10px;
	font-size: 14pt;
}
input[name=search] {
	width: 300px;
}
#viewList {
	margin-top: 50px;
}
#viewList li {
	padding: 10px 0px;
}
#viewList span {
	display: block;
}
#viewList span.content {
	font-weight: bold;
	font-size: 15pt;
}
</style>
</head>

<body>

<div id="searchBox">
	<form method="GET" action="./index.php">
	<input type="text" name="search" placeholder="search text" />
	<input type="submit" value="search">
	</form>
</div>

<div id="viewList">
<ul>
<?php	foreach($list as $key => $val){ ?>
	<li>
		<div class="viewBox">
			<span class="time"><?=$val['wtime']?></span>
	<?php if($val['secret'] == 'N'){ ?>
			<span class="content"><?=$val['content']?></span>
	<?php }else{ ?>
			<span class="content">** secret **</span>
	<?php } ?>
		</div>
	</li>
<?php	} ?>
</ul>
</div>
<!-- /1ab17eacf75146f906e92265c1d2df76/ -->
</body>
</html>
