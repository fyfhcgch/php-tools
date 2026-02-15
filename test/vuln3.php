<?php
highlight_file(__FILE__);

class User {
    public $username;
    public $isAdmin = false;

    function __destruct() {
        if ($this->isAdmin) {
            include('flag.php');
            echo $flag;
        }
    }
}

if (isset($_GET['data'])) {
    $user = unserialize($_GET['data']);
} else {
    echo "请提供 data 参数";
}
?>
