package android.support.v4.p012g;

import android.util.Log;
import java.io.Writer;

/* renamed from: android.support.v4.g.e */
public class C0112e extends Writer {
    private final String f381a;
    private StringBuilder f382b;

    public C0112e(String str) {
        this.f382b = new StringBuilder(128);
        this.f381a = str;
    }

    private void m637a() {
        if (this.f382b.length() > 0) {
            Log.d(this.f381a, this.f382b.toString());
            this.f382b.delete(0, this.f382b.length());
        }
    }

    public void close() {
        m637a();
    }

    public void flush() {
        m637a();
    }

    public void write(char[] cArr, int i, int i2) {
        for (int i3 = 0; i3 < i2; i3++) {
            char c = cArr[i + i3];
            if (c == '\n') {
                m637a();
            } else {
                this.f382b.append(c);
            }
        }
    }
}
