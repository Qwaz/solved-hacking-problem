package android.support.v7.widget;

import android.support.v7.view.menu.C0207y;
import android.support.v7.view.menu.C0264i;
import android.support.v7.view.menu.ad;

/* renamed from: android.support.v7.widget.s */
class C0302s implements C0207y {
    final /* synthetic */ C0294k f1592a;

    private C0302s(C0294k c0294k) {
        this.f1592a = c0294k;
    }

    public void m2840a(C0264i c0264i, boolean z) {
        if (c0264i instanceof ad) {
            ((ad) c0264i).m2152p().m2115a(false);
        }
        C0207y a = this.f1592a.m2177a();
        if (a != null) {
            a.m1754a(c0264i, z);
        }
    }

    public boolean m2841a(C0264i c0264i) {
        if (c0264i == null) {
            return false;
        }
        this.f1592a.f1563h = ((ad) c0264i).getItem().getItemId();
        C0207y a = this.f1592a.m2177a();
        return a != null ? a.m1755a(c0264i) : false;
    }
}
