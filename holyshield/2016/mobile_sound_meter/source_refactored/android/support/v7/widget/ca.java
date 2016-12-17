package android.support.v7.widget;

import android.view.View;

class ca implements Runnable {
    final /* synthetic */ by f1426a;

    ca(by byVar) {
        this.f1426a = byVar;
    }

    public void run() {
        View e = this.f1426a.m2571e();
        if (e != null && e.getWindowToken() != null) {
            this.f1426a.m2567c();
        }
    }
}
