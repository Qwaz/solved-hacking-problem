package android.support.v4.view;

import android.graphics.Paint;
import android.os.Build.VERSION;
import android.view.View;

/* renamed from: android.support.v4.view.x */
public class C0061x {
    static final af f266a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 17) {
            f266a = new ae();
        } else if (i >= 16) {
            f266a = new ad();
        } else if (i >= 14) {
            f266a = new ac();
        } else if (i >= 11) {
            f266a = new ab();
        } else if (i >= 9) {
            f266a = new aa();
        } else {
            f266a = new C0037y();
        }
    }

    public static int m379a(View view) {
        return f266a.m246a(view);
    }

    public static void m380a(View view, int i, int i2, int i3, int i4) {
        f266a.m247a(view, i, i2, i3, i4);
    }

    public static void m381a(View view, int i, Paint paint) {
        f266a.m248a(view, i, paint);
    }

    public static void m382a(View view, Paint paint) {
        f266a.m249a(view, paint);
    }

    public static void m383a(View view, Runnable runnable) {
        f266a.m250a(view, runnable);
    }

    public static boolean m384a(View view, int i) {
        return f266a.m251a(view, i);
    }

    public static void m385b(View view) {
        f266a.m252b(view);
    }

    public static int m386c(View view) {
        return f266a.m253c(view);
    }

    public static int m387d(View view) {
        return f266a.m254d(view);
    }

    public static boolean m388e(View view) {
        return f266a.m255e(view);
    }
}
