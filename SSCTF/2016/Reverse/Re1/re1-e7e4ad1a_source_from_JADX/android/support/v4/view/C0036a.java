package android.support.v4.view;

import android.os.Build.VERSION;

/* renamed from: android.support.v4.view.a */
public class C0036a {
    static final C0039b f249a;

    static {
        if (VERSION.SDK_INT >= 17) {
            f249a = new C0041d();
        } else {
            f249a = new C0040c();
        }
    }

    public static int m245a(int i, int i2) {
        return f249a.m301a(i, i2);
    }
}
