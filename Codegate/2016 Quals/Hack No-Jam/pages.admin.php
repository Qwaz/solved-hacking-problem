<?php
	session_start();
	if ($_SESSION['login'][1] != "admin") die();

		session_start();
		session_destroy();
		include("./mod/db_conn.php");
		$result = mysql_query("select flag from flag");
		$row = mysql_fetch_row($result);
		$flag = $row[0];
		die("FLAG : " . $flag);
