package android.support.v7.p014a;

import android.support.v7.p015b.C0243l;

/* renamed from: android.support.v7.a.af */
class af implements Runnable {
    final /* synthetic */ ae f615a;

    af(ae aeVar) {
        this.f615a = aeVar;
    }

    public void run() {
        if ((this.f615a.f586F & 1) != 0) {
            this.f615a.m1691f(0);
        }
        if ((this.f615a.f586F & 4096) != 0) {
            this.f615a.m1691f(C0243l.AppCompatTheme_ratingBarStyleSmall);
        }
        this.f615a.f585E = false;
        this.f615a.f586F = 0;
    }
}
