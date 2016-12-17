package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.view.VelocityTracker;

/* renamed from: android.support.v4.h.bp */
public final class bp {
    static final bs f442a;

    static {
        if (VERSION.SDK_INT >= 11) {
            f442a = new br();
        } else {
            f442a = new bq();
        }
    }

    public static float m971a(VelocityTracker velocityTracker, int i) {
        return f442a.m972a(velocityTracker, i);
    }
}
