package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.view.View;

/* renamed from: android.support.v4.h.dm */
class dm implements dy {
    dh f463a;
    boolean f464b;

    dm(dh dhVar) {
        this.f463a = dhVar;
    }

    public void m1270a(View view) {
        this.f464b = false;
        if (this.f463a.f457e >= 0) {
            bu.m981a(view, 2, null);
        }
        if (this.f463a.f455c != null) {
            Runnable a = this.f463a.f455c;
            this.f463a.f455c = null;
            a.run();
        }
        Object tag = view.getTag(2113929216);
        dy dyVar = tag instanceof dy ? (dy) tag : null;
        if (dyVar != null) {
            dyVar.m1267a(view);
        }
    }

    public void m1271b(View view) {
        if (this.f463a.f457e >= 0) {
            bu.m981a(view, this.f463a.f457e, null);
            this.f463a.f457e = -1;
        }
        if (VERSION.SDK_INT >= 16 || !this.f464b) {
            if (this.f463a.f456d != null) {
                Runnable b = this.f463a.f456d;
                this.f463a.f456d = null;
                b.run();
            }
            Object tag = view.getTag(2113929216);
            dy dyVar = tag instanceof dy ? (dy) tag : null;
            if (dyVar != null) {
                dyVar.m1268b(view);
            }
            this.f464b = true;
        }
    }

    public void m1272c(View view) {
        Object tag = view.getTag(2113929216);
        dy dyVar = tag instanceof dy ? (dy) tag : null;
        if (dyVar != null) {
            dyVar.m1269c(view);
        }
    }
}
