package android.support.v4.widget;

import android.os.Build.VERSION;

/* renamed from: android.support.v4.widget.j */
public class C0071j {
    static final C0072k f322b;
    Object f323a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 14) {
            f322b = new C0075n();
        } else if (i >= 9) {
            f322b = new C0074m();
        } else {
            f322b = new C0073l();
        }
    }

    public void m492a(int i, int i2, int i3, int i4, int i5) {
        f322b.m500a(this.f323a, i, i2, i3, i4, i5);
    }

    public boolean m493a() {
        return f322b.m501a(this.f323a);
    }

    public int m494b() {
        return f322b.m502b(this.f323a);
    }

    public int m495c() {
        return f322b.m503c(this.f323a);
    }

    public int m496d() {
        return f322b.m506f(this.f323a);
    }

    public int m497e() {
        return f322b.m507g(this.f323a);
    }

    public boolean m498f() {
        return f322b.m504d(this.f323a);
    }

    public void m499g() {
        f322b.m505e(this.f323a);
    }
}
