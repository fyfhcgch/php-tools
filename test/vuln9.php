<?php
highlight_file(__FILE__);

class EasyCheck {
    public $auth = false;
    public $cmd = "whoami";

    public function __destruct() {
        if ($this->auth === true) {
            system($this->cmd);
        } else {
            echo "Access Denied!";
        }
    }
}

if (isset($_GET['data'])) {
    unserialize($_GET['data']);
} else {
    echo "请提供 GET 参数 data";
}
?>
