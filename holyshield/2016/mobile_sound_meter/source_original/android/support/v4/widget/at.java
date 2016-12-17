package android.support.v4.widget;

import android.content.Context;
import android.os.Build.VERSION;
import android.view.animation.Interpolator;

public final class at {
    Object f543a;
    au f544b;

    private at(int i, Context context, Interpolator interpolator) {
        if (i >= 14) {
            this.f544b = new ax();
        } else if (i >= 9) {
            this.f544b = new aw();
        } else {
            this.f544b = new av();
        }
        this.f543a = this.f544b.m1480a(context, interpolator);
    }

    public static at m1467a(Context context) {
        return m1468a(context, null);
    }

    public static at m1468a(Context context, Interpolator interpolator) {
        return new at(VERSION.SDK_INT, context, interpolator);
    }

    public void m1469a(int i, int i2, int i3, int i4) {
        this.f544b.m1481a(this.f543a, i, i2, i3, i4);
    }

    public void m1470a(int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        this.f544b.m1482a(this.f543a, i, i2, i3, i4, i5, i6, i7, i8);
    }

    public void m1471a(int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10) {
        this.f544b.m1483a(this.f543a, i, i2, i3, i4, i5, i6, i7, i8, i9, i10);
    }

    public boolean m1472a() {
        return this.f544b.m1484a(this.f543a);
    }

    public boolean m1473a(int i, int i2, int i3, int i4, int i5, int i6) {
        return this.f544b.m1485a(this.f543a, i, i2, i3, i4, i5, i6);
    }

    public int m1474b() {
        return this.f544b.m1486b(this.f543a);
    }

    public int m1475c() {
        return this.f544b.m1487c(this.f543a);
    }

    public int m1476d() {
        return this.f544b.m1491g(this.f543a);
    }

    public float m1477e() {
        return this.f544b.m1488d(this.f543a);
    }

    public boolean m1478f() {
        return this.f544b.m1489e(this.f543a);
    }

    public void m1479g() {
        this.f544b.m1490f(this.f543a);
    }
}
