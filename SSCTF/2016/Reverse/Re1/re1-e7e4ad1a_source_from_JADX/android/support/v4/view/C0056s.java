package android.support.v4.view;

import android.os.Build.VERSION;
import android.view.VelocityTracker;

/* renamed from: android.support.v4.view.s */
public class C0056s {
    static final C0057v f265a;

    static {
        if (VERSION.SDK_INT >= 11) {
            f265a = new C0059u();
        } else {
            f265a = new C0058t();
        }
    }

    public static float m369a(VelocityTracker velocityTracker, int i) {
        return f265a.m371a(velocityTracker, i);
    }

    public static float m370b(VelocityTracker velocityTracker, int i) {
        return f265a.m372b(velocityTracker, i);
    }
}
