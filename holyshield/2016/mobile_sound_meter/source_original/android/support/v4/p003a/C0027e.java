package android.support.v4.p003a;

import android.content.Context;
import android.os.Build.VERSION;

/* renamed from: android.support.v4.a.e */
public final class C0027e {
    private static final C0029h f202a;

    static {
        if (VERSION.SDK_INT >= 23) {
            f202a = new C0030g();
        } else {
            f202a = new C0029h();
        }
    }

    public static int m292a(Context context, String str, String str2) {
        return f202a.m294a(context, str, str2);
    }

    public static String m293a(String str) {
        return f202a.m295a(str);
    }
}
