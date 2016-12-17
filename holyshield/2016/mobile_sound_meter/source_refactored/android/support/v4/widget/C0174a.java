package android.support.v4.widget;

import android.content.res.Resources;
import android.os.SystemClock;
import android.support.v4.p004h.az;
import android.support.v4.p004h.bu;
import android.support.v7.p015b.C0243l;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnTouchListener;
import android.view.ViewConfiguration;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.Interpolator;

/* renamed from: android.support.v4.widget.a */
public abstract class C0174a implements OnTouchListener {
    private static final int f508r;
    private final C0178c f509a;
    private final Interpolator f510b;
    private final View f511c;
    private Runnable f512d;
    private float[] f513e;
    private float[] f514f;
    private int f515g;
    private int f516h;
    private float[] f517i;
    private float[] f518j;
    private float[] f519k;
    private boolean f520l;
    private boolean f521m;
    private boolean f522n;
    private boolean f523o;
    private boolean f524p;
    private boolean f525q;

    static {
        f508r = ViewConfiguration.getTapTimeout();
    }

    public C0174a(View view) {
        this.f509a = new C0178c();
        this.f510b = new AccelerateInterpolator();
        this.f513e = new float[]{0.0f, 0.0f};
        this.f514f = new float[]{Float.MAX_VALUE, Float.MAX_VALUE};
        this.f517i = new float[]{0.0f, 0.0f};
        this.f518j = new float[]{0.0f, 0.0f};
        this.f519k = new float[]{Float.MAX_VALUE, Float.MAX_VALUE};
        this.f511c = view;
        DisplayMetrics displayMetrics = Resources.getSystem().getDisplayMetrics();
        int i = (int) ((1575.0f * displayMetrics.density) + 0.5f);
        int i2 = (int) ((displayMetrics.density * 315.0f) + 0.5f);
        m1410a((float) i, (float) i);
        m1414b((float) i2, (float) i2);
        m1411a(1);
        m1420e(Float.MAX_VALUE, Float.MAX_VALUE);
        m1418d(0.2f, 0.2f);
        m1416c(1.0f, 1.0f);
        m1415b(f508r);
        m1417c(500);
        m1419d(500);
    }

    private float m1390a(float f, float f2, float f3, float f4) {
        float f5;
        float b = C0174a.m1396b(f * f2, 0.0f, f3);
        b = m1407f(f2 - f4, b) - m1407f(f4, b);
        if (b < 0.0f) {
            f5 = -this.f510b.getInterpolation(-b);
        } else if (b <= 0.0f) {
            return 0.0f;
        } else {
            f5 = this.f510b.getInterpolation(b);
        }
        return C0174a.m1396b(f5, -1.0f, 1.0f);
    }

    private float m1391a(int i, float f, float f2, float f3) {
        float a = m1390a(this.f513e[i], f2, this.f514f[i], f);
        if (a == 0.0f) {
            return 0.0f;
        }
        float f4 = this.f517i[i];
        float f5 = this.f518j[i];
        float f6 = this.f519k[i];
        f4 *= f3;
        return a > 0.0f ? C0174a.m1396b(a * f4, f5, f6) : -C0174a.m1396b((-a) * f4, f5, f6);
    }

    private boolean m1393a() {
        C0178c c0178c = this.f509a;
        int f = c0178c.m1539f();
        int e = c0178c.m1538e();
        return (f != 0 && m1422f(f)) || (e != 0 && m1421e(e));
    }

    private static float m1396b(float f, float f2, float f3) {
        return f > f3 ? f3 : f < f2 ? f2 : f;
    }

    private static int m1397b(int i, int i2, int i3) {
        return i > i3 ? i3 : i < i2 ? i2 : i;
    }

    private void m1398b() {
        if (this.f512d == null) {
            this.f512d = new C0179d();
        }
        this.f523o = true;
        this.f521m = true;
        if (this.f520l || this.f516h <= 0) {
            this.f512d.run();
        } else {
            bu.m987a(this.f511c, this.f512d, (long) this.f516h);
        }
        this.f520l = true;
    }

    private void m1402c() {
        if (this.f521m) {
            this.f523o = false;
        } else {
            this.f509a.m1534b();
        }
    }

    private void m1404d() {
        long uptimeMillis = SystemClock.uptimeMillis();
        MotionEvent obtain = MotionEvent.obtain(uptimeMillis, uptimeMillis, 3, 0.0f, 0.0f, 0);
        this.f511c.onTouchEvent(obtain);
        obtain.recycle();
    }

    private float m1407f(float f, float f2) {
        if (f2 == 0.0f) {
            return 0.0f;
        }
        switch (this.f515g) {
            case C0243l.View_android_theme /*0*/:
            case C0243l.View_android_focusable /*1*/:
                return f < f2 ? f >= 0.0f ? 1.0f - (f / f2) : (this.f523o && this.f515g == 1) ? 1.0f : 0.0f : 0.0f;
            case C0243l.View_paddingStart /*2*/:
                return f < 0.0f ? f / (-f2) : 0.0f;
            default:
                return 0.0f;
        }
    }

    public C0174a m1410a(float f, float f2) {
        this.f519k[0] = f / 1000.0f;
        this.f519k[1] = f2 / 1000.0f;
        return this;
    }

    public C0174a m1411a(int i) {
        this.f515g = i;
        return this;
    }

    public C0174a m1412a(boolean z) {
        if (this.f524p && !z) {
            m1402c();
        }
        this.f524p = z;
        return this;
    }

    public abstract void m1413a(int i, int i2);

    public C0174a m1414b(float f, float f2) {
        this.f518j[0] = f / 1000.0f;
        this.f518j[1] = f2 / 1000.0f;
        return this;
    }

    public C0174a m1415b(int i) {
        this.f516h = i;
        return this;
    }

    public C0174a m1416c(float f, float f2) {
        this.f517i[0] = f / 1000.0f;
        this.f517i[1] = f2 / 1000.0f;
        return this;
    }

    public C0174a m1417c(int i) {
        this.f509a.m1533a(i);
        return this;
    }

    public C0174a m1418d(float f, float f2) {
        this.f513e[0] = f;
        this.f513e[1] = f2;
        return this;
    }

    public C0174a m1419d(int i) {
        this.f509a.m1535b(i);
        return this;
    }

    public C0174a m1420e(float f, float f2) {
        this.f514f[0] = f;
        this.f514f[1] = f2;
        return this;
    }

    public abstract boolean m1421e(int i);

    public abstract boolean m1422f(int i);

    public boolean onTouch(View view, MotionEvent motionEvent) {
        boolean z = true;
        if (!this.f524p) {
            return false;
        }
        switch (az.m895a(motionEvent)) {
            case C0243l.View_android_theme /*0*/:
                this.f522n = true;
                this.f520l = false;
                break;
            case C0243l.View_android_focusable /*1*/:
            case C0243l.View_paddingEnd /*3*/:
                m1402c();
                break;
            case C0243l.View_paddingStart /*2*/:
                break;
        }
        this.f509a.m1532a(m1391a(0, motionEvent.getX(), (float) view.getWidth(), (float) this.f511c.getWidth()), m1391a(1, motionEvent.getY(), (float) view.getHeight(), (float) this.f511c.getHeight()));
        if (!this.f523o && m1393a()) {
            m1398b();
        }
        if (!(this.f525q && this.f523o)) {
            z = false;
        }
        return z;
    }
}
