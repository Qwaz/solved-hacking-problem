package android.support.v7.widget;

import android.view.View;

class cq implements Runnable {
    final /* synthetic */ View f1469a;
    final /* synthetic */ cp f1470b;

    cq(cp cpVar, View view) {
        this.f1470b = cpVar;
        this.f1469a = view;
    }

    public void run() {
        this.f1470b.smoothScrollTo(this.f1469a.getLeft() - ((this.f1470b.getWidth() - this.f1469a.getWidth()) / 2), 0);
        this.f1470b.f1460a = null;
    }
}
