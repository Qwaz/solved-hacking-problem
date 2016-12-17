package android.support.v4.widget;

import android.support.v4.p004h.bu;

/* renamed from: android.support.v4.widget.d */
class C0179d implements Runnable {
    final /* synthetic */ C0174a f556a;

    private C0179d(C0174a c0174a) {
        this.f556a = c0174a;
    }

    public void run() {
        if (this.f556a.f523o) {
            if (this.f556a.f521m) {
                this.f556a.f521m = false;
                this.f556a.f509a.m1531a();
            }
            C0178c c = this.f556a.f509a;
            if (c.m1536c() || !this.f556a.m1393a()) {
                this.f556a.f523o = false;
                return;
            }
            if (this.f556a.f522n) {
                this.f556a.f522n = false;
                this.f556a.m1404d();
            }
            c.m1537d();
            this.f556a.m1413a(c.m1540g(), c.m1541h());
            bu.m986a(this.f556a.f511c, (Runnable) this);
        }
    }
}
