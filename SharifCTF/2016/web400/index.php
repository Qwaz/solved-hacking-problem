<?php
    if (extract_teamname_from_cookie("hackme") === false)
        die("\n\n\n");

define('SHPA_WEB_PAGE_TO_ROOT', '');
require_once SHPA_WEB_PAGE_TO_ROOT . 'function.php';

shpaEchoHeader();
shpaCheckAuth();

$iserror = false;
$classname = "info";
if (isset($_POST['Upload'])) {
    global $mysqli;
    shpaCheckToken($_REQUEST['user_token'], $_SESSION['session_token'], 'login.php');

    $fileContents = $_FILES['cvfile']['type'];
    $fileName = $_FILES['cvfile']['name'];


    //<svg onload=alert(1)>
    shpaDatabaseConnect();
    $user = $_POST['first'];
    $userget = $_GET["first"];
    $user = stripslashes($user);

    if (!is_null($user) && strlen($user) > 1 && $fileContents=="application/pdf") {
        if(!is_null($userget) && strlen($userget) > 1){
            $isAttack = preg_match('/<(?:\w+)\W+?[\w]/', $userget);
            $usertrim = trim(preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $userget));
            $user=$userget;
            if($isAttack && $usertrim==$userget){
                $iserror = true;
                $classname = "danger";
                shpaMessagePush("error: saved in sensitive_log_881027.txt");
            }
        }
        else{
            $iserror = false;
            $classname = "info";
            shpaMessagePush("Done");
        }

    } else {
        $iserror = true;
        $classname = "danger";
        shpaMessagePush("please fill First Name and Attach valid Cv file(pdf)!!!");
    }

}
shpaGenerateSessionToken();
$messagesHtml = messagesPopAllToHtml();
?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml\">

<head>

    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>

    <title>Cv Page</title>

    <link rel="stylesheet" type="text/css" href="<?php echo SHPA_WEB_PAGE_TO_ROOT ?>bootstrap/css/bootstrap.min.css"/>
    <link rel="stylesheet" type="text/css" href="<?php echo SHPA_WEB_PAGE_TO_ROOT ?>bootstrap/css/docs.min.css"/>
    <link rel="stylesheet" type="text/css" href="<?php echo SHPA_WEB_PAGE_TO_ROOT ?>bootstrap/css/style.css"/>


</head>
<body>
<div class=''>
    <header role="banner" id="top" class="navbar navbar-static-top bs-docs-nav">
        <div class="container">
            <div class="navbar-header">
                <a class="navbar-brand">Hack Me!</a></div>
            <nav class="collapse navbar-collapse" id="bs-navbar">
                <ul class="nav navbar-nav">
                    <li><a href="index.php">Index</a></li>
                    <li><a href="ping.php">Ping</a></li>
                    <li><a href="file.php?page=aGVscC5wZGY">help.pdf</a></li>
                    <li><a href="logout.php">LogOut</a></li>
                </ul>
            </nav>
        </div>
    </header>
</div>
<div tabindex="-1" id="content" class="bs-docs-header">
    <div class="container"><h1>CV Page</h1>
    </div>
</div>
<div class='container'>
    <div class='row'>
        <div class='col-md-3'></div>
        <div class='col-md-6'>
            <div class='bs-example'>
                <form method="post" enctype="multipart/form-data">
                    <p>upload your cv please!</p>
                    <?php if (!is_null($messagesHtml) && strlen($messagesHtml) > 2) { ?>
                        <div id="callout-input-needs-type" class="bs-callout bs-callout-<?php echo $classname ?>">
                            <p class="">
                                <?php echo $messagesHtml ?>
                                <?php if (!$iserror) { ?>
                                    <a href="<?php echo $fileName ?>"> Download Cv <?php  xecho($user." - "); echo $fileName ?></a>
                                <?php } ?>
                            </p>
                        </div>
                    <?php } ?>

                    <div class="form-group">
                        <label for="exampleInputName">FirstName</label>
                        <input type="text" placeholder="First Name" id="exampleInputName" name="first"
                               class="form-control">
                    </div>
                    <div class="form-group">
                        <label for="exampleInputcv">Cv(pdf)</label>
                        <input name="cvfile" type="file"/>
                    </div>
                    <input class="btn btn-default" type="submit" value="Upload" name="Upload">
                    <?php echo shpaTokenField() ?>
                </form>
            </div>
        </div>
        <div class='col-md-3'></div>
    </div>
</div>
</body>
</html>
