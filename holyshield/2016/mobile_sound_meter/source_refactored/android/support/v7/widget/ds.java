package android.support.v7.widget;

import android.support.v4.p004h.dz;
import android.view.View;

class ds extends dz {
    final /* synthetic */ int f1552a;
    final /* synthetic */ dq f1553b;
    private boolean f1554c;

    ds(dq dqVar, int i) {
        this.f1553b = dqVar;
        this.f1552a = i;
        this.f1554c = false;
    }

    public void m2788a(View view) {
        this.f1553b.f1532a.setVisibility(0);
    }

    public void m2789b(View view) {
        if (!this.f1554c) {
            this.f1553b.f1532a.setVisibility(this.f1552a);
        }
    }

    public void m2790c(View view) {
        this.f1554c = true;
    }
}
