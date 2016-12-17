package android.support.v7.p014a;

import android.support.v4.p004h.bu;

/* renamed from: android.support.v7.a.aj */
class aj implements Runnable {
    final /* synthetic */ ae f619a;

    aj(ae aeVar) {
        this.f619a = aeVar;
    }

    public void run() {
        this.f619a.f594o.showAtLocation(this.f619a.f593n, 55, 0, 0);
        this.f619a.m1697u();
        bu.m991b(this.f619a.f593n, 0.0f);
        this.f619a.f596q = bu.m1000i(this.f619a.f593n).m1225a(1.0f);
        this.f619a.f596q.m1227a(new ak(this));
    }
}
