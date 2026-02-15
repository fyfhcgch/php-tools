<?php
highlight_file(__FILE__);

class FileReader {
    public $filename;
    public $content;

    function __toString() {
        return file_get_contents($this->filename);
    }
}

class Logger {
    public $logFile;
    public $data;

    function __wakeup() {
        file_put_contents($this->logFile, $this->data);
    }

    function __destruct() {
        echo $this->logFile;
    }
}

if (isset($_POST['obj'])) {
    unserialize($_POST['obj']);
} else {
    echo "请提供 POST 参数 obj";
}
?>
