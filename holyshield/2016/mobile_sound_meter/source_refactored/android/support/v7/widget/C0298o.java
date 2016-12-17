package android.support.v7.widget;

import android.view.View;

/* renamed from: android.support.v7.widget.o */
class C0298o implements Runnable {
    final /* synthetic */ C0294k f1585a;
    private C0301r f1586b;

    public C0298o(C0294k c0294k, C0301r c0301r) {
        this.f1585a = c0294k;
        this.f1586b = c0301r;
    }

    public void run() {
        this.f1585a.c.m2132f();
        View view = (View) this.f1585a.f;
        if (!(view == null || view.getWindowToken() == null || !this.f1586b.m2273d())) {
            this.f1585a.f1579x = this.f1586b;
        }
        this.f1585a.f1581z = null;
    }
}
