#include <gb/gb.h>
#include <stdio.h>

const char * str = "Hello World!";

void main(void)
{
    UBYTE i;

    puts(" A : Send 0x64");
    puts(" B : Send 0x55");
    puts(" UP : Recv");

    while(1) {
        i = waitpad(J_A | J_B | J_UP);
        waitpadup();

        if(i == J_A) {
            printf("Sending 64... ");
            _io_out = 0x64;
            send_byte();
            /* Wait for IO completion... */
            while(_io_status == IO_SENDING && joypad() == 0);
            if(_io_status == IO_IDLE)
                printf("OK\n");
            else
                printf("#%d\n", _io_status);
        } else if(i == J_B) {
            printf("Sending 55... ");
            _io_out = 0x55;
            send_byte();
            /* Wait for IO completion... */
            while(_io_status == IO_SENDING && joypad() == 0);
            if(_io_status == IO_IDLE)
                printf("OK\n");
            else
                printf("#%d\n", _io_status);
        } else if(i == J_UP) {
            printf("Receiving... ");
            receive_byte();
            /* Wait for IO completion... */
            while(_io_status == IO_RECEIVING && joypad() == 0);
            if(_io_status == IO_IDLE)
                printf("OK %c(%d)\n", _io_in, _io_in);
            else
                printf("#%d\n", _io_status);
        }
    }
}
