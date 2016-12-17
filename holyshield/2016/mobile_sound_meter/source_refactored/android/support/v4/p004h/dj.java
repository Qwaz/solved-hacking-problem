package android.support.v4.p004h;

import android.view.View;
import android.view.animation.Interpolator;
import java.util.WeakHashMap;

/* renamed from: android.support.v4.h.dj */
class dj implements dr {
    WeakHashMap f458a;

    dj() {
        this.f458a = null;
    }

    private void m1245a(View view) {
        if (this.f458a != null) {
            Runnable runnable = (Runnable) this.f458a.get(view);
            if (runnable != null) {
                view.removeCallbacks(runnable);
            }
        }
    }

    private void m1246d(dh dhVar, View view) {
        Object tag = view.getTag(2113929216);
        dy dyVar = tag instanceof dy ? (dy) tag : null;
        Runnable a = dhVar.f455c;
        Runnable b = dhVar.f456d;
        dhVar.f455c = null;
        dhVar.f456d = null;
        if (a != null) {
            a.run();
        }
        if (dyVar != null) {
            dyVar.m1267a(view);
            dyVar.m1268b(view);
        }
        if (b != null) {
            b.run();
        }
        if (this.f458a != null) {
            this.f458a.remove(view);
        }
    }

    private void m1247e(dh dhVar, View view) {
        Runnable runnable = this.f458a != null ? (Runnable) this.f458a.get(view) : null;
        if (runnable == null) {
            runnable = new dk(this, dhVar, view, null);
            if (this.f458a == null) {
                this.f458a = new WeakHashMap();
            }
            this.f458a.put(view, runnable);
        }
        view.removeCallbacks(runnable);
        view.post(runnable);
    }

    public long m1248a(dh dhVar, View view) {
        return 0;
    }

    public void m1249a(dh dhVar, View view, float f) {
        m1247e(dhVar, view);
    }

    public void m1250a(dh dhVar, View view, long j) {
    }

    public void m1251a(dh dhVar, View view, dy dyVar) {
        view.setTag(2113929216, dyVar);
    }

    public void m1252a(dh dhVar, View view, ea eaVar) {
    }

    public void m1253a(dh dhVar, View view, Interpolator interpolator) {
    }

    public void m1254b(dh dhVar, View view) {
        m1247e(dhVar, view);
    }

    public void m1255b(dh dhVar, View view, float f) {
        m1247e(dhVar, view);
    }

    public void m1256b(dh dhVar, View view, long j) {
    }

    public void m1257c(dh dhVar, View view) {
        m1245a(view);
        m1246d(dhVar, view);
    }
}
