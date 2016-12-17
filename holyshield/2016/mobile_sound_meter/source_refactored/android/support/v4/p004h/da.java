package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.view.View;
import android.view.ViewParent;

/* renamed from: android.support.v4.h.da */
public final class da {
    static final dc f452a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 21) {
            f452a = new de();
        } else if (i >= 19) {
            f452a = new dd();
        } else if (i >= 14) {
            f452a = new db();
        } else {
            f452a = new df();
        }
    }

    public static void m1183a(ViewParent viewParent, View view) {
        f452a.m1190a(viewParent, view);
    }

    public static void m1184a(ViewParent viewParent, View view, int i, int i2, int i3, int i4) {
        f452a.m1191a(viewParent, view, i, i2, i3, i4);
    }

    public static void m1185a(ViewParent viewParent, View view, int i, int i2, int[] iArr) {
        f452a.m1192a(viewParent, view, i, i2, iArr);
    }

    public static boolean m1186a(ViewParent viewParent, View view, float f, float f2) {
        return f452a.m1193a(viewParent, view, f, f2);
    }

    public static boolean m1187a(ViewParent viewParent, View view, float f, float f2, boolean z) {
        return f452a.m1194a(viewParent, view, f, f2, z);
    }

    public static boolean m1188a(ViewParent viewParent, View view, View view2, int i) {
        return f452a.m1195a(viewParent, view, view2, i);
    }

    public static void m1189b(ViewParent viewParent, View view, View view2, int i) {
        f452a.m1196b(viewParent, view, view2, i);
    }
}
