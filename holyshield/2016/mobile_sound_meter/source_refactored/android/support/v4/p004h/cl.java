package android.support.v4.p004h;

import android.view.View;
import android.view.View.AccessibilityDelegate;

/* renamed from: android.support.v4.h.cl */
class cl {
    public static void m1154a(View view, Object obj) {
        view.setAccessibilityDelegate((AccessibilityDelegate) obj);
    }

    public static boolean m1155a(View view, int i) {
        return view.canScrollVertically(i);
    }
}
