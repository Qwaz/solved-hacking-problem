package android.support.v4.p004h;

import android.support.v4.p004h.p013a.C0126f;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;

/* renamed from: android.support.v4.h.c */
class C0152c implements C0151j {
    final /* synthetic */ C0147a f446a;
    final /* synthetic */ C0150b f447b;

    C0152c(C0150b c0150b, C0147a c0147a) {
        this.f447b = c0150b;
        this.f446a = c0147a;
    }

    public void m1107a(View view, int i) {
        this.f446a.m827a(view, i);
    }

    public void m1108a(View view, Object obj) {
        this.f446a.m828a(view, new C0126f(obj));
    }

    public boolean m1109a(View view, AccessibilityEvent accessibilityEvent) {
        return this.f446a.m832b(view, accessibilityEvent);
    }

    public boolean m1110a(ViewGroup viewGroup, View view, AccessibilityEvent accessibilityEvent) {
        return this.f446a.m831a(viewGroup, view, accessibilityEvent);
    }

    public void m1111b(View view, AccessibilityEvent accessibilityEvent) {
        this.f446a.m834d(view, accessibilityEvent);
    }

    public void m1112c(View view, AccessibilityEvent accessibilityEvent) {
        this.f446a.m833c(view, accessibilityEvent);
    }

    public void m1113d(View view, AccessibilityEvent accessibilityEvent) {
        this.f446a.m829a(view, accessibilityEvent);
    }
}
