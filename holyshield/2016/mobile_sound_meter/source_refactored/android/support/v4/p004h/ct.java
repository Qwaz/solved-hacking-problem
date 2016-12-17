package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.view.ViewConfiguration;

/* renamed from: android.support.v4.h.ct */
public final class ct {
    static final cy f451a;

    static {
        if (VERSION.SDK_INT >= 14) {
            f451a = new cx();
        } else if (VERSION.SDK_INT >= 11) {
            f451a = new cw();
        } else if (VERSION.SDK_INT >= 8) {
            f451a = new cv();
        } else {
            f451a = new cu();
        }
    }

    public static boolean m1177a(ViewConfiguration viewConfiguration) {
        return f451a.m1178a(viewConfiguration);
    }
}
