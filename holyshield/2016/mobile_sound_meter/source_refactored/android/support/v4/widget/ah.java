package android.support.v4.widget;

import android.os.Build.VERSION;
import android.view.View;
import android.widget.PopupWindow;

public final class ah {
    static final an f527a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 23) {
            f527a = new aj();
        } else if (i >= 21) {
            f527a = new ai();
        } else if (i >= 19) {
            f527a = new am();
        } else if (i >= 9) {
            f527a = new al();
        } else {
            f527a = new ak();
        }
    }

    public static void m1432a(PopupWindow popupWindow, int i) {
        f527a.m1435a(popupWindow, i);
    }

    public static void m1433a(PopupWindow popupWindow, View view, int i, int i2, int i3) {
        f527a.m1436a(popupWindow, view, i, i2, i3);
    }

    public static void m1434a(PopupWindow popupWindow, boolean z) {
        f527a.m1437a(popupWindow, z);
    }
}
