<?php
    if (extract_teamname_from_cookie("hackme") === false)
        exit;

define('SHPA_WEB_PAGE_TO_ROOT', '');
require_once SHPA_WEB_PAGE_TO_ROOT . 'function.php';

shpaEchoHeader();
shpaCheckAuth();

if( isset( $_POST[ 'Ping' ]  ) ) {
    shpaCheckToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $target = $_REQUEST[ 'IP' ];
    $target = stripslashes( $target );

    // Split the IP into 4 octects
    $octet = explode( ".", $target );

    // Check IF each octet is an integer
    if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
        // If all 4 octets are int's put the IP back together.
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

        // Determine OS and execute the ping command.
        if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
            // Windows
            $cmd = shell_exec( 'ping  ' . $target );
        }
        else {
            // *nix
            $cmd = shell_exec( 'ping  -c 4 ' . $target );
        }

        // Feedback for the end user
        shpaMessagePush("<pre>{$cmd}</pre>");
    }
    else {
        // Ops. Let the user name theres a mistake
        shpaMessagePush("<pre>ERROR: You have entered an invalid IP.</pre>");
    }
}

shpaGenerateSessionToken();
$messagesHtml = messagesPopAllToHtml();
?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml\">

<head>

    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>

    <title>Ping Page</title>

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
    <div class="container"><h1>Ping Page</h1>
    </div>
</div>
<div class='container'>
    <div class='row'>
        <div class='col-md-3'></div>
        <div class='col-md-6'>
            <div class='bs-example'>
                <form method="post" enctype="multipart/form-data">
                    <p>Ping!</p>
                    <?php if (!is_null($messagesHtml) && strlen($messagesHtml) > 2) { ?>
                        <div id="callout-input-needs-type" class="bs-callout bs-callout-info">
                            <p class="">
                                <?php echo $messagesHtml ?>
                            </p>
                        </div>
                    <?php } ?>
                    <div class="form-group">
                        <input type="text" placeholder="IP" id="exampleInputName" name="IP"
                               class="form-control">
                    </div>

                    <input class="btn btn-default" type="submit" value="Ping" name="Ping">
                    <?php echo shpaTokenField() ?>
                </form>
            </div>
        </div>
        <div class='col-md-3'></div>
    </div>
</div>
</body>
</html>
