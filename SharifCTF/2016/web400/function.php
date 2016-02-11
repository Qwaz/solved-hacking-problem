<?php
if( !defined( 'SHPA_WEB_PAGE_TO_ROOT' ) ) {
    die( 'SHPA System error- WEB_PAGE_TO_ROOT undefined' );
    exit;
}

session_start();


$_Config = array();
$_Config[ 'db_server' ]   = '127.0.0.1';
$_Config[ 'db_database' ] = 'hack.me';
$_Config[ 'db_user' ]     = 'app';
$_Config[ 'db_password' ] = 'password@@';

$mysqli;

//error_reporting(0);
function exception_handler($exception) {
    echo "Uncaught exception\n";
}

set_exception_handler('exception_handler');


function shpaDatabaseConnect() {
    global $_Config;
    global $mysqli;
    $mysqli = new mysqli($_Config["db_server"],$_Config["db_user"], $_Config["db_password"], $_Config["db_database"]);

    if (mysqli_connect_errno()) {
        error_log("Connect failed: " . mysqli_connect_error());
        exit();
    }
}


function shpaEchoHeader(){
    Header( 'Cache-Control: no-cache, must-revalidate');
    Header( 'Content-Type: text/html;charset=utf-8' );
    //Header( 'Expires: Tue, 23 Jun 2009 12:00:00 GMT' );
}
function shpaRedirect( $pLocation ) {
    session_commit();
    header( "Location: {$pLocation}" );
    exit;
}

function shpaIsLoggedIn() {
    return isset( $_SESSION[ 'username' ] );
}
function shpaLogout()
{
    unset($_SESSION['username']);
}

function shpaCurrentUser() {
    return ( isset( $_SESSION[ 'username' ]) ? $_SESSION[ 'username' ] : '') ;
}
function shpaLogin( $pUsername ) {
    $_SESSION[ 'username' ] = $pUsername;
}
function shpaCheckAuth(){
    if( !shpaIsLoggedIn() ) {
        shpaRedirect( 'login.php' );
    }
}


function shpaGenerateSessionToken() {  # Generate a brand new (CSRF) token
    if( isset( $_SESSION[ 'session_token' ] ) ) {
        shpaDestroySessionToken();
    }
    $_SESSION[ 'session_token' ] = md5( uniqid() );
}
function shpaDestroySessionToken() {  # Destroy any session with the name 'session_token'
    unset( $_SESSION[ 'session_token' ] );
}
function shpaTokenField() {  # Return a field for the (CSRF) token
    return "<input type='hidden' name='user_token' value='{$_SESSION[ 'session_token' ]}' />";
}
function shpaCheckToken( $user_token, $session_token, $returnURL ) {  # Validate the given (CSRF) token
    if( $user_token !== $session_token || !isset( $session_token ) ) {
        shpaMessagePush( 'CSRF token is incorrect' );
        shpaRedirect( $returnURL );
    }
}

// Start message functions --

function shpaMessagePush( $pMessage ) {
    if( !isset( $_SESSION[ 'messages' ] ) ) {
        $_SESSION[ 'messages' ] = array();
    }
    $_SESSION[ 'messages' ][] = $pMessage;
}


function shpaMessagePop() {
    if( !isset( $_SESSION[ 'messages' ] ) || count( $_SESSION[ 'messages' ] ) == 0 ) {
        return false;
    }
    return array_shift( $_SESSION[ 'messages' ] );
}


function messagesPopAllToHtml() {
    $messagesHtml = '';
    while( $message = shpaMessagePop() ) {
        $messagesHtml .= "<div class=\"message\">{$message}</div>";
    }

    return $messagesHtml;
}

// --END (message functions)

function xssafe($data,$encoding='UTF-8')
{
    return htmlspecialchars($data,ENT_QUOTES | ENT_HTML401,$encoding);
}
function xecho($data)
{
    echo xssafe($data);
}

?>
