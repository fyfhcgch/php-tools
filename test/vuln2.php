<?php
highlight_file(__FILE__);
error_reporting(0);

class Happy {
    private $cmd;
    private $content;

    public function __construct($cmd, $content) {
        $this->cmd = $cmd;
        $this->content = $content;
    }

    public function __call($name, $arguments) {
        call_user_func($this->cmd, $this->content);
    }

    public function __wakeup() {
        die("Wishes can be fulfilled");
    }
}

class Nevv {
    private $happiness;

    public function __invoke() {
        return $this->happiness->check();
    }
}

class Rabbit {
    private $aspiration;

    public function __set($name, $val) {
        return $this->aspiration->family;
    }
}

class Year {
    public $key;
    public $rabbit;

    public function __construct($key) {
        $this->key = $key;
    }

    public function firecrackers() {
        return $this->rabbit->wish = "allkill QAQ";
    }

    public function __get($name) {
        $name = $this->rabbit;
        $name();
    }

    public function __destruct() {
        if ($this->key == "happy new year") {
            $this->firecrackers();
        } else {
            print("Welcome 2023!!!!!");
        }
    }
}

if (isset($_GET['pop'])) {
    $a = unserialize($_GET['pop']);
} else {
    echo "过新年啊~过个吉祥年~";
}
?>
