package me.daei.soundmeter;

/* renamed from: me.daei.soundmeter.a */
public class Obfuscator2 {
    public static float encrypt(float f) {
        int j = 0;
        char[] cArr = new char[]{'Z', '\u000e', '\u0011', '\u000b', '\f', '\u0006', '\u001d', '\u001c', '\'', '.', '*', ')', '6', '@', '?', 'P', 'N', 'L', 'G', '=', ':', ',', '\u001f', '\u0010', '\u0013', '\u0001', '\u0004', '-', '9', 'E', 'O', 'R', 'V', 'Q', 'S', '\\', ']', ';', '1', '!', '\u0016', '\r', '\n', '\u0012', '\u0003', '\u0000', '\u0005', '<', '>', 'F', 'K', 'J', 'W', '[', '4', '\u001b', '\u001a', '2', '/', 'C', 'H', 'X', '\u0002', '\t', '\b', '\u0007', '+', '(', '7', 'M', 'T', 'U', '\u0014', '%', '5', '\u001e', '\"', 'A', 'D', 'I', '#', '\u0015', 'Y', '\u0018', '0', 'B', '\u0017', '\u000f', '&', '8', '\u0019', ' ', '$', '3'};
        char[] cArr2 = new char[]{'!', '@', '`', 'A', 'a', '\"', 'B', 'b', '#', 'C', 'c', 'd', 'D', '$', 'E', '%', 'e', 'F', 'f', '&', '\'', 'G', 'g', 'h', 'H', '(', ')', 'I', 'i', 'j', 'J', '*', '+', 'K', 'k', ',', 'l', 'L', '-', 'M', 'm', 'n', '.', 'N', 'O', 'o', '/', '0', '1', '2', 'P', 'p', 'Q', 'q', 'R', 'r', '3', 'S', 's', 't', 'T', '4', '5', '6', '7', '8', 'U', 'V', 'W', 'X', 'u', 'v', 'w', 'x', '9', 'Y', 'y', ':', 'Z', 'z', ';', '[', '{', '|', '\\', '<', '=', ']', '}', '_', '^', '~', '>', '?'};
        int i = 0;
        int count = 0;
        while (i < 1000 && ((int) f) != cArr2[i]) {
            count++;
            i++;
        }
        float count_f = (float) count;
        i = 33;
        while (j < 1000 && count_f != ((float) cArr[j])) {
            i++;
            j++;
        }
        float i_f = (float) i;
        return (((char) ((int) i_f)) < '!' || ((char) ((int) i_f)) > '/') ?
                (((char) ((int) i_f)) < 'a' || ((char) ((int) i_f)) > 'o') ?
                        (((char) ((int) i_f)) < 'A' || ((char) ((int) i_f)) > 'O') ?
                                (((char) ((int) i_f)) < '0' || ((char) ((int) i_f)) > ':') ?
                                        (((char) ((int) i_f)) < 'P' || ((char) ((int) i_f)) > 'Z') ?
                                                (((char) ((int) i_f)) < 'p' || ((char) ((int) i_f)) > 'z') ?
                                                        i_f :
                                                        i_f - 64.0f :
                                                i_f + 32.0f :
                                        i_f + 32.0f :
                                i_f - 32.0f :
                        i_f - 32.0f :
                i_f + 64.0f;
    }
}
