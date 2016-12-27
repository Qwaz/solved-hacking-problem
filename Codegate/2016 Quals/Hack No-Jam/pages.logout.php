<?php
	session_start();
	session_destroy();
	die("<script>window.location.href='./';</script>");
