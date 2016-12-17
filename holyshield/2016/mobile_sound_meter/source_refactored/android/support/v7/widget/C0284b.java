package android.support.v7.widget;

import android.support.v4.p004h.dh;
import android.support.v4.p004h.dy;
import android.view.View;

/* renamed from: android.support.v7.widget.b */
public class C0284b implements dy {
    int f1335a;
    final /* synthetic */ C0283a f1336b;
    private boolean f1337c;

    protected C0284b(C0283a c0283a) {
        this.f1336b = c0283a;
        this.f1337c = false;
    }

    public C0284b m2533a(dh dhVar, int i) {
        this.f1336b.f1091f = dhVar;
        this.f1335a = i;
        return this;
    }

    public void m2534a(View view) {
        super.setVisibility(0);
        this.f1337c = false;
    }

    public void m2535b(View view) {
        if (!this.f1337c) {
            this.f1336b.f1091f = null;
            super.setVisibility(this.f1335a);
        }
    }

    public void m2536c(View view) {
        this.f1337c = true;
    }
}
