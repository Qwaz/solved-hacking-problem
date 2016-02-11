<?php
    if (extract_teamname_from_cookie("hackme") === false)
        exit;

define('SHPA_WEB_PAGE_TO_ROOT', '');
require_once SHPA_WEB_PAGE_TO_ROOT . 'function.php';

shpaEchoHeader();
shpaCheckAuth();
shpaLogout();
shpaCheckAuth();
?>