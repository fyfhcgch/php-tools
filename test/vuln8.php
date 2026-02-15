<?php
highlight_file(__FILE__);

class A {
    public $obj;

    public function __wakeup() {
        if (isset($this->obj)) {
            $this->obj->doSomething();
        }
    }
}

class B {
    public $cmd;

    public function doSomething() {
        if (preg_match('/system|exec|shell_exec|passthru|eval/i', $this->cmd)) {
            die("危险函数禁止使用");
        }
        @call_user_func($this->cmd);
    }
}

class C {
    public $content;

    public function __invoke() {
        file_put_contents("flag.txt", $this->content);
        echo file_get_contents("/flag");
    }
}

if (isset($_COOKIE['token'])) {
    unserialize($_COOKIE['token']);
} else {
    echo "请提供 Cookie: token";
}
?>
