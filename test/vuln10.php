<?php
highlight_file(__FILE__);

class User {
    public $name;
    public $profile;

    public function __destruct() {
        echo "Goodbye, " . $this->profile;
    }
}

class FileViewer {
    public $filename;

    public function __toString() {
        if (isset($this->filename)) {
            return file_get_contents($this->filename);
        }
        return "No file specified.";
    }
}

if (isset($_GET['payload'])) {
    unserialize($_GET['payload']);
} else {
    echo "请提供 GET 参数 payload";
}
?>
