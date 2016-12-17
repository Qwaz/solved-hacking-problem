package android.support.v7.widget;

import android.support.v4.p004h.bu;

/* renamed from: android.support.v7.widget.h */
class C0292h implements Runnable {
    final /* synthetic */ ActionBarOverlayLayout f1560a;

    C0292h(ActionBarOverlayLayout actionBarOverlayLayout) {
        this.f1560a = actionBarOverlayLayout;
    }

    public void run() {
        this.f1560a.m2313k();
        this.f1560a.f1130x = bu.m1000i(this.f1560a.f1111e).m1230b((float) (-this.f1560a.f1111e.getHeight())).m1227a(this.f1560a.f1131y);
    }
}
