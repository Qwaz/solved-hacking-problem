<?php
$_SESSION[id] = "";
session_destroy();
echo "<script>location.href='?page=login';</script>";
?>
