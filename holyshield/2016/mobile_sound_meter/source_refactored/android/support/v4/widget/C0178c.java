package android.support.v4.widget;

import android.view.animation.AnimationUtils;

/* renamed from: android.support.v4.widget.c */
class C0178c {
    private int f545a;
    private int f546b;
    private float f547c;
    private float f548d;
    private long f549e;
    private long f550f;
    private int f551g;
    private int f552h;
    private long f553i;
    private float f554j;
    private int f555k;

    public C0178c() {
        this.f549e = Long.MIN_VALUE;
        this.f553i = -1;
        this.f550f = 0;
        this.f551g = 0;
        this.f552h = 0;
    }

    private float m1529a(float f) {
        return ((-4.0f * f) * f) + (4.0f * f);
    }

    private float m1530a(long j) {
        if (j < this.f549e) {
            return 0.0f;
        }
        if (this.f553i < 0 || j < this.f553i) {
            return C0174a.m1396b(((float) (j - this.f549e)) / ((float) this.f545a), 0.0f, 1.0f) * 0.5f;
        }
        long j2 = j - this.f553i;
        return (C0174a.m1396b(((float) j2) / ((float) this.f555k), 0.0f, 1.0f) * this.f554j) + (1.0f - this.f554j);
    }

    public void m1531a() {
        this.f549e = AnimationUtils.currentAnimationTimeMillis();
        this.f553i = -1;
        this.f550f = this.f549e;
        this.f554j = 0.5f;
        this.f551g = 0;
        this.f552h = 0;
    }

    public void m1532a(float f, float f2) {
        this.f547c = f;
        this.f548d = f2;
    }

    public void m1533a(int i) {
        this.f545a = i;
    }

    public void m1534b() {
        long currentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
        this.f555k = C0174a.m1397b((int) (currentAnimationTimeMillis - this.f549e), 0, this.f546b);
        this.f554j = m1530a(currentAnimationTimeMillis);
        this.f553i = currentAnimationTimeMillis;
    }

    public void m1535b(int i) {
        this.f546b = i;
    }

    public boolean m1536c() {
        return this.f553i > 0 && AnimationUtils.currentAnimationTimeMillis() > this.f553i + ((long) this.f555k);
    }

    public void m1537d() {
        if (this.f550f == 0) {
            throw new RuntimeException("Cannot compute scroll delta before calling start()");
        }
        long currentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
        float a = m1529a(m1530a(currentAnimationTimeMillis));
        long j = currentAnimationTimeMillis - this.f550f;
        this.f550f = currentAnimationTimeMillis;
        this.f551g = (int) ((((float) j) * a) * this.f547c);
        this.f552h = (int) ((((float) j) * a) * this.f548d);
    }

    public int m1538e() {
        return (int) (this.f547c / Math.abs(this.f547c));
    }

    public int m1539f() {
        return (int) (this.f548d / Math.abs(this.f548d));
    }

    public int m1540g() {
        return this.f551g;
    }

    public int m1541h() {
        return this.f552h;
    }
}
