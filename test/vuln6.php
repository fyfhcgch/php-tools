<?php
highlight_file(__FILE__);

class Test {
    public $name = "guest";
    public $isAdmin = false;

    public function check() {
        if ($this->isAdmin === true && $this->name === "admin") {
            include('flag.php');
            echo $flag;
        } else {
            echo "not admin";
        }
    }
}

if (isset($_GET['data'])) {
    $obj = unserialize($_GET['data']);
    if (is_object($obj)) {
        $obj->check();
    }
} else {
    echo "请提供 data 参数";
}
?>
