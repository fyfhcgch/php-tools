<?php
highlight_file(__FILE__);

class Base {
    protected $func;

    function __call($name, $args) {
        call_user_func($this->func, $args[0]);
    }
}

class A {
    public $obj;

    function __wakeup() {
        $this->obj->run();
    }
}

class B {
    private $cmd;

    function run() {
        system($this->cmd);
    }
}

class C {
    public $param;

    function __construct() {
        $this->param = new Base();
    }

    function __toString() {
        $this->param->{$this->param->func}($this->param->func);
        return "";
    }
}

if (isset($_GET['ser'])) {
    unserialize(base64_decode($_GET['ser']));
} else {
    echo "请提供 GET 参数 ser (base64编码)";
}
?>
