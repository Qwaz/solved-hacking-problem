package android.support.v4.p003a;

import android.view.View;

/* renamed from: android.support.v4.a.u */
class C0043u extends aa {
    final /* synthetic */ C0042t f317a;

    C0043u(C0042t c0042t) {
        this.f317a = c0042t;
    }

    public View m409a(int i) {
        if (this.f317a.f275I != null) {
            return this.f317a.f275I.findViewById(i);
        }
        throw new IllegalStateException("Fragment does not have a view");
    }

    public boolean m410a() {
        return this.f317a.f275I != null;
    }
}
