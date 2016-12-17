package android.support.v4.p004h;

import android.view.View;
import java.lang.ref.WeakReference;

/* renamed from: android.support.v4.h.dk */
class dk implements Runnable {
    WeakReference f459a;
    dh f460b;
    final /* synthetic */ dj f461c;

    private dk(dj djVar, dh dhVar, View view) {
        this.f461c = djVar;
        this.f459a = new WeakReference(view);
        this.f460b = dhVar;
    }

    public void run() {
        View view = (View) this.f459a.get();
        if (view != null) {
            this.f461c.m1246d(this.f460b, view);
        }
    }
}
