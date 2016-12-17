package android.support.v7.view;

import android.support.v4.p004h.dz;
import android.view.View;

/* renamed from: android.support.v7.view.m */
class C0257m extends dz {
    final /* synthetic */ C0256l f905a;
    private boolean f906b;
    private int f907c;

    C0257m(C0256l c0256l) {
        this.f905a = c0256l;
        this.f906b = false;
        this.f907c = 0;
    }

    void m2052a() {
        this.f907c = 0;
        this.f906b = false;
        this.f905a.m2044c();
    }

    public void m2053a(View view) {
        if (!this.f906b) {
            this.f906b = true;
            if (this.f905a.f902d != null) {
                this.f905a.f902d.m1267a(null);
            }
        }
    }

    public void m2054b(View view) {
        int i = this.f907c + 1;
        this.f907c = i;
        if (i == this.f905a.f899a.size()) {
            if (this.f905a.f902d != null) {
                this.f905a.f902d.m1268b(null);
            }
            m2052a();
        }
    }
}
