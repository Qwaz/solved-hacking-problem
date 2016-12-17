package me.daei.soundmeter;

/* renamed from: me.daei.soundmeter.g */
class C0314g implements Runnable {
    final /* synthetic */ SecondActivity f1630a;

    C0314g(SecondActivity secondActivity) {
        this.f1630a = secondActivity;
    }

    public void run() {
        while (this.f1630a.f1620n) {
            try {
                if (this.f1630a.f1619m) {
                    this.f1630a.f1618l = this.f1630a.f1623q.m2874a();
                    if (this.f1630a.f1618l > 0.0f && this.f1630a.f1618l < 1000000.0f) {
                        C0315h.m2880a(20.0f * ((float) Math.log10((double) this.f1630a.f1618l)));
                        this.f1630a.f1622p.m2883a();
                    }
                }
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
                this.f1630a.f1619m = false;
            }
        }
    }
}
