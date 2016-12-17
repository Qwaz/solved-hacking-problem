package android.support.v7.view;

import android.support.v4.p004h.dh;
import android.support.v4.p004h.dy;
import android.support.v4.p004h.dz;
import android.view.animation.Interpolator;
import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: android.support.v7.view.l */
public class C0256l {
    private final ArrayList f899a;
    private long f900b;
    private Interpolator f901c;
    private dy f902d;
    private boolean f903e;
    private final dz f904f;

    public C0256l() {
        this.f900b = -1;
        this.f904f = new C0257m(this);
        this.f899a = new ArrayList();
    }

    private void m2044c() {
        this.f903e = false;
    }

    public C0256l m2045a(long j) {
        if (!this.f903e) {
            this.f900b = j;
        }
        return this;
    }

    public C0256l m2046a(dh dhVar) {
        if (!this.f903e) {
            this.f899a.add(dhVar);
        }
        return this;
    }

    public C0256l m2047a(dh dhVar, dh dhVar2) {
        this.f899a.add(dhVar);
        dhVar2.m1231b(dhVar.m1224a());
        this.f899a.add(dhVar2);
        return this;
    }

    public C0256l m2048a(dy dyVar) {
        if (!this.f903e) {
            this.f902d = dyVar;
        }
        return this;
    }

    public C0256l m2049a(Interpolator interpolator) {
        if (!this.f903e) {
            this.f901c = interpolator;
        }
        return this;
    }

    public void m2050a() {
        if (!this.f903e) {
            Iterator it = this.f899a.iterator();
            while (it.hasNext()) {
                dh dhVar = (dh) it.next();
                if (this.f900b >= 0) {
                    dhVar.m1226a(this.f900b);
                }
                if (this.f901c != null) {
                    dhVar.m1229a(this.f901c);
                }
                if (this.f902d != null) {
                    dhVar.m1227a(this.f904f);
                }
                dhVar.m1233c();
            }
            this.f903e = true;
        }
    }

    public void m2051b() {
        if (this.f903e) {
            Iterator it = this.f899a.iterator();
            while (it.hasNext()) {
                ((dh) it.next()).m1232b();
            }
            this.f903e = false;
        }
    }
}
