package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.os.Bundle;
import android.support.v4.p004h.p013a.C0126f;
import android.support.v4.p004h.p013a.C0138r;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;

/* renamed from: android.support.v4.h.a */
public class C0147a {
    private static final C0148d f426b;
    private static final Object f427c;
    final Object f428a;

    static {
        if (VERSION.SDK_INT >= 16) {
            f426b = new C0154e();
        } else if (VERSION.SDK_INT >= 14) {
            f426b = new C0150b();
        } else {
            f426b = new C0149g();
        }
        f427c = f426b.m904a();
    }

    public C0147a() {
        this.f428a = f426b.m905a(this);
    }

    public C0138r m825a(View view) {
        return f426b.m903a(f427c, view);
    }

    Object m826a() {
        return this.f428a;
    }

    public void m827a(View view, int i) {
        f426b.m906a(f427c, view, i);
    }

    public void m828a(View view, C0126f c0126f) {
        f426b.m907a(f427c, view, c0126f);
    }

    public void m829a(View view, AccessibilityEvent accessibilityEvent) {
        f426b.m913d(f427c, view, accessibilityEvent);
    }

    public boolean m830a(View view, int i, Bundle bundle) {
        return f426b.m908a(f427c, view, i, bundle);
    }

    public boolean m831a(ViewGroup viewGroup, View view, AccessibilityEvent accessibilityEvent) {
        return f426b.m910a(f427c, viewGroup, view, accessibilityEvent);
    }

    public boolean m832b(View view, AccessibilityEvent accessibilityEvent) {
        return f426b.m909a(f427c, view, accessibilityEvent);
    }

    public void m833c(View view, AccessibilityEvent accessibilityEvent) {
        f426b.m912c(f427c, view, accessibilityEvent);
    }

    public void m834d(View view, AccessibilityEvent accessibilityEvent) {
        f426b.m911b(f427c, view, accessibilityEvent);
    }
}
