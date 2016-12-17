package android.support.v7.p014a;

import android.support.v4.p004h.bu;
import android.support.v4.p004h.dz;
import android.view.View;

/* renamed from: android.support.v7.a.al */
class al extends dz {
    final /* synthetic */ ae f621a;

    al(ae aeVar) {
        this.f621a = aeVar;
    }

    public void m1752a(View view) {
        this.f621a.f593n.setVisibility(0);
        this.f621a.f593n.sendAccessibilityEvent(32);
        if (this.f621a.f593n.getParent() != null) {
            bu.m1002k((View) this.f621a.f593n.getParent());
        }
    }

    public void m1753b(View view) {
        bu.m991b(this.f621a.f593n, 1.0f);
        this.f621a.f596q.m1227a(null);
        this.f621a.f596q = null;
    }
}
