package android.support.v4.p002c;

import android.util.Log;
import java.io.Writer;

/* renamed from: android.support.v4.c.b */
public class C0034b extends Writer {
    private final String f189a;
    private StringBuilder f190b;

    public C0034b(String str) {
        this.f190b = new StringBuilder(128);
        this.f189a = str;
    }

    private void m203a() {
        if (this.f190b.length() > 0) {
            Log.d(this.f189a, this.f190b.toString());
            this.f190b.delete(0, this.f190b.length());
        }
    }

    public void close() {
        m203a();
    }

    public void flush() {
        m203a();
    }

    public void write(char[] cArr, int i, int i2) {
        for (int i3 = 0; i3 < i2; i3++) {
            char c = cArr[i + i3];
            if (c == '\n') {
                m203a();
            } else {
                this.f190b.append(c);
            }
        }
    }
}
