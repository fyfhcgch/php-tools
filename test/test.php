<?php
class X
{
    public $x = __FILE__;
    function __construct($x)
    {
        $this->x = $x;
    }
    function __wakeup()
    {
        if ($this->x !== __FILE__) {
            $this->x = __FILE__;
        }
    }
    function __destruct()
    {
        highlight_file($this->x);
        //flag is in fllllllag.php
    }
}
if (isset($_REQUEST['x'])) {
    @unserialize($_REQUEST['x']);
} else {
    highlight_file(__FILE__);
}