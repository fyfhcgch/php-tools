<?php
highlight_file(__FILE__);

class User {
    private $username = "user";
    protected $role = "guest";

    public function __destruct() {
        if ($this->username === "admin" && $this->role === "root") {
            include('flag.php');
            echo $flag;
        }
    }
}

if (isset($_POST['payload'])) {
    $data = base64_decode($_POST['payload']);
    unserialize($data);
} else {
    echo "请提供 POST 参数 payload (base64编码)";
}
?>
