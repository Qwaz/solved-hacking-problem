package android.support.v4.p004h;

import android.os.Bundle;
import android.view.View;
import android.view.View.AccessibilityDelegate;

/* renamed from: android.support.v4.h.k */
class C0159k {
    public static Object m1331a(C0155m c0155m) {
        return new C0160l(c0155m);
    }

    public static Object m1332a(Object obj, View view) {
        return ((AccessibilityDelegate) obj).getAccessibilityNodeProvider(view);
    }

    public static boolean m1333a(Object obj, View view, int i, Bundle bundle) {
        return ((AccessibilityDelegate) obj).performAccessibilityAction(view, i, bundle);
    }
}
