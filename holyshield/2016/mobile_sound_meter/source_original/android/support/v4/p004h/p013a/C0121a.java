package android.support.v4.p004h.p013a;

import android.os.Build.VERSION;
import android.view.accessibility.AccessibilityEvent;

/* renamed from: android.support.v4.h.a.a */
public final class C0121a {
    private static final C0122e f413a;

    static {
        if (VERSION.SDK_INT >= 19) {
            f413a = new C0125c();
        } else if (VERSION.SDK_INT >= 14) {
            f413a = new C0124b();
        } else {
            f413a = new C0123d();
        }
    }

    public static ae m667a(AccessibilityEvent accessibilityEvent) {
        return new ae(accessibilityEvent);
    }
}
