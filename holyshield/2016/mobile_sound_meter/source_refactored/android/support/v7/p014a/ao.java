package android.support.v7.p014a;

import android.support.v4.p004h.bu;
import android.support.v4.p004h.dz;
import android.view.View;

/* renamed from: android.support.v7.a.ao */
class ao extends dz {
    final /* synthetic */ an f625a;

    ao(an anVar) {
        this.f625a = anVar;
    }

    public void m1766b(View view) {
        this.f625a.f623a.f593n.setVisibility(8);
        if (this.f625a.f623a.f594o != null) {
            this.f625a.f623a.f594o.dismiss();
        } else if (this.f625a.f623a.f593n.getParent() instanceof View) {
            bu.m1002k((View) this.f625a.f623a.f593n.getParent());
        }
        this.f625a.f623a.f593n.removeAllViews();
        this.f625a.f623a.f596q.m1227a(null);
        this.f625a.f623a.f596q = null;
    }
}
