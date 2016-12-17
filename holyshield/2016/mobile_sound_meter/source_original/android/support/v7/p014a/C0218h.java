package android.support.v7.p014a;

import android.view.View;

/* renamed from: android.support.v7.a.h */
class C0218h implements Runnable {
    final /* synthetic */ View f778a;
    final /* synthetic */ View f779b;
    final /* synthetic */ C0215e f780c;

    C0218h(C0215e c0215e, View view, View view2) {
        this.f780c = c0215e;
        this.f778a = view;
        this.f779b = view2;
    }

    public void run() {
        C0215e.m1928b(this.f780c.f770w, this.f778a, this.f779b);
    }
}
