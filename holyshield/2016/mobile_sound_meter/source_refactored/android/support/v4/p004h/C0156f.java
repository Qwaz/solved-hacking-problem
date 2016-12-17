package android.support.v4.p004h;

import android.os.Bundle;
import android.support.v4.p004h.p013a.C0126f;
import android.support.v4.p004h.p013a.C0138r;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;

/* renamed from: android.support.v4.h.f */
class C0156f implements C0155m {
    final /* synthetic */ C0147a f472a;
    final /* synthetic */ C0154e f473b;

    C0156f(C0154e c0154e, C0147a c0147a) {
        this.f473b = c0154e;
        this.f472a = c0147a;
    }

    public Object m1313a(View view) {
        C0138r a = this.f472a.m825a(view);
        return a != null ? a.m809a() : null;
    }

    public void m1314a(View view, int i) {
        this.f472a.m827a(view, i);
    }

    public void m1315a(View view, Object obj) {
        this.f472a.m828a(view, new C0126f(obj));
    }

    public boolean m1316a(View view, int i, Bundle bundle) {
        return this.f472a.m830a(view, i, bundle);
    }

    public boolean m1317a(View view, AccessibilityEvent accessibilityEvent) {
        return this.f472a.m832b(view, accessibilityEvent);
    }

    public boolean m1318a(ViewGroup viewGroup, View view, AccessibilityEvent accessibilityEvent) {
        return this.f472a.m831a(viewGroup, view, accessibilityEvent);
    }

    public void m1319b(View view, AccessibilityEvent accessibilityEvent) {
        this.f472a.m834d(view, accessibilityEvent);
    }

    public void m1320c(View view, AccessibilityEvent accessibilityEvent) {
        this.f472a.m833c(view, accessibilityEvent);
    }

    public void m1321d(View view, AccessibilityEvent accessibilityEvent) {
        this.f472a.m829a(view, accessibilityEvent);
    }
}
