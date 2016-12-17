package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.view.ViewGroup.MarginLayoutParams;

/* renamed from: android.support.v4.h.am */
public final class am {
    static final an f433a;

    static {
        if (VERSION.SDK_INT >= 17) {
            f433a = new ap();
        } else {
            f433a = new ao();
        }
    }

    public static int m850a(MarginLayoutParams marginLayoutParams) {
        return f433a.m852a(marginLayoutParams);
    }

    public static int m851b(MarginLayoutParams marginLayoutParams) {
        return f433a.m853b(marginLayoutParams);
    }
}
