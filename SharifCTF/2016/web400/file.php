<?php
    if (extract_teamname_from_cookie("hackme") === false)
        exit;

define('SHPA_WEB_PAGE_TO_ROOT', '');
require_once SHPA_WEB_PAGE_TO_ROOT . 'function.php';

shpaEchoHeader();
shpaCheckAuth();
// The page we wish to display
$file = $_GET[ 'page' ];

$attachment_location = $_SERVER["DOCUMENT_ROOT"] . "/hack.me/" . base64_decode($file);
//die($attachment_location);
if (file_exists($attachment_location)) {

    if (strpos(realpath($attachment_location), "/var/www/") !== 0)
	die();

    header($_SERVER["SERVER_PROTOCOL"] . " 200 OK");
    header("Cache-Control: public"); // needed for i.e.

    header("Content-Transfer-Encoding: Binary");
    header("Content-Length:".filesize($attachment_location));
    header("Content-Disposition: attachment; filename=file.pdf");
    header("Content-Type: application/pdf");

	$data = file_get_contents($attachment_location);
	$data = sharifctf_internal_put_it($data, "hackme");
	echo $data;
    die();
} else {
    die("Error: File not found.");
}
?>