package android.support.v7.widget;

import android.support.v4.p004h.bu;

class ck implements Runnable {
    final /* synthetic */ by f1448a;

    private ck(by byVar) {
        this.f1448a = byVar;
    }

    public void run() {
        if (this.f1448a.f1381g != null && bu.m1009r(this.f1448a.f1381g) && this.f1448a.f1381g.getCount() > this.f1448a.f1381g.getChildCount() && this.f1448a.f1381g.getChildCount() <= this.f1448a.f1377b) {
            this.f1448a.f1379e.setInputMethodMode(2);
            this.f1448a.m2567c();
        }
    }
}
