<?php
highlight_file(__FILE__);

class Start {
    public $next;

    public function __destruct() {
        $this->next->check();
    }
}

class Modifier {
    protected $var;

    public function __append($value) {
        include($value);
    }

    public function __call($name, $arguments) {
        $this->__append($this->var);
    }
}

class Show {
    public $source;
    public $str;

    public function __get($key) {
        return $this->str->func();
    }

    public function check() {
        return $this->source->data;
    }
}

if (isset($_GET['input'])) {
    unserialize($_GET['input']);
} else {
    echo "请提供 GET 参数 input";
}
?>
