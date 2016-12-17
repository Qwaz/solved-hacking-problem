package android.support.v4.p004h;

import android.os.Build.VERSION;

/* renamed from: android.support.v4.h.q */
public final class C0164q {
    static final C0165r f479a;

    static {
        if (VERSION.SDK_INT >= 17) {
            f479a = new C0167t();
        } else {
            f479a = new C0166s();
        }
    }

    public static int m1347a(int i, int i2) {
        return f479a.m1348a(i, i2);
    }
}
