<?php
    if (extract_teamname_from_cookie("hackme") === false)
        exit;

define('SHPA_WEB_PAGE_TO_ROOT', '');
require_once SHPA_WEB_PAGE_TO_ROOT . 'function.php';

shpaEchoHeader();

if (isset($_POST['Login'])) {
    global $mysqli;
    shpaCheckToken($_REQUEST['user_token'], $_SESSION['session_token'], 'login.php');

    shpaDatabaseConnect();
    $user = $_POST['username'];

    $user = stripslashes($user);
    //$user = $mysqli->real_escape_string( $user );

    $pass = $_POST['password'];
    $pass = stripslashes($pass);
    $pass = $mysqli->real_escape_string($pass);
    $pass = md5($pass);

    $query = "SELECT * FROM `hack.me`.user where username='" . $user . "' and password='" . $pass . "';";
    //echo $query . "\n";
    if ($mysqli->multi_query($query)) {
        do {
            if ($result = $mysqli->store_result()) {
                $has_row = false;
                while ($row = $result->fetch_row()) {
                    $has_row = true;
                    if ($pass == "26a340b11385ebc2db3b462ec2fdfda4" and $user == "admin") {
                        shpaLogin($user);
                        shpaRedirect(SHPA_WEB_PAGE_TO_ROOT . 'index.php');
                    } else if($row[1]!="admin") {
                        printf("%s %s %s %s %s\n", $row[0], $row[1], $row[2],$row[3],$row[4]);
                        printf("-----------------\n");
                    }
                }
                if (!$has_row) {
                    shpaMessagePush("User Name or Password incorrect");
                }
                $result->free();
            }

        } while ($mysqli->next_result());
    }
    $mysqli->close();

}

shpaGenerateSessionToken();
$messagesHtml = messagesPopAllToHtml();
?>


<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml\">

<head>

    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>

    <title>Login</title>

    <link rel="stylesheet" type="text/css" href="<?php echo SHPA_WEB_PAGE_TO_ROOT ?>bootstrap/css/bootstrap.min.css"/>
    <link rel="stylesheet" type="text/css" href="<?php echo SHPA_WEB_PAGE_TO_ROOT ?>bootstrap/css/docs.min.css"/>
    <link rel="stylesheet" type="text/css" href="<?php echo SHPA_WEB_PAGE_TO_ROOT ?>bootstrap/css/style.css"/>


</head>
<body>
<div tabindex="-1" id="content" class="bs-docs-header">
    <div class="container"><h1>Login Page</h1>


    </div>
</div>
<div class='container'>
    <div class='row'>
        <div class='col-md-3'></div>
        <div class='col-md-6'>
            <div class='bs-example'>
                <form method="post">
                    <?php if (!is_null($messagesHtml) && strlen($messagesHtml) > 2) { ?>
                        <div id="callout-input-needs-type" class="bs-callout bs-callout-danger">
                            <p class=""><?php echo $messagesHtml ?></p>
                        </div>
                    <?php } ?>

                    <div class="form-group">
                        <label for="exampleInputEmail1">User Name</label>
                        <input type="text" placeholder="UserName" id="exampleInputEmail1" name="username"
                               class="form-control">
                    </div>
                    <div class="form-group">
                        <label for="exampleInputPassword1">Password</label>
                        <input type="password" placeholder="Password" id="exampleInputPassword1" name="password"
                               class="form-control">
                    </div>

                    <input class="btn btn-default" type="submit" value="Login" name="Login">
                    <?php echo shpaTokenField() ?>
                </form>
            </div>
        </div>
        <div class='col-md-3'></div>
    </div>
</div>
</body>
</html>

