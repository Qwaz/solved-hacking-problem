package android.support.v7.p014a;

import android.support.v4.p004h.bu;
import android.support.v4.p004h.dz;
import android.view.View;

/* renamed from: android.support.v7.a.be */
class be extends dz {
    final /* synthetic */ bd f724a;

    be(bd bdVar) {
        this.f724a = bdVar;
    }

    public void m1874b(View view) {
        if (this.f724a.f695C && this.f724a.f717t != null) {
            bu.m979a(this.f724a.f717t, 0.0f);
            bu.m979a(this.f724a.f714q, 0.0f);
        }
        this.f724a.f714q.setVisibility(8);
        this.f724a.f714q.setTransitioning(false);
        this.f724a.f700H = null;
        this.f724a.m1865i();
        if (this.f724a.f713p != null) {
            bu.m1002k(this.f724a.f713p);
        }
    }
}
