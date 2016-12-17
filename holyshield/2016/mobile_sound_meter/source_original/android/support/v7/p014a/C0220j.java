package android.support.v7.p014a;

import android.view.View;

/* renamed from: android.support.v7.a.j */
class C0220j implements Runnable {
    final /* synthetic */ View f784a;
    final /* synthetic */ View f785b;
    final /* synthetic */ C0215e f786c;

    C0220j(C0215e c0215e, View view, View view2) {
        this.f786c = c0215e;
        this.f784a = view;
        this.f785b = view2;
    }

    public void run() {
        C0215e.m1928b(this.f786c.f753f, this.f784a, this.f785b);
    }
}
