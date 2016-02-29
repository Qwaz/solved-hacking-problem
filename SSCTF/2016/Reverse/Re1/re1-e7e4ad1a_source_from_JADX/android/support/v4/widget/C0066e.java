package android.support.v4.widget;

import android.graphics.Canvas;
import android.os.Build.VERSION;

/* renamed from: android.support.v4.widget.e */
public class C0066e {
    private static final C0067h f320b;
    private Object f321a;

    static {
        if (VERSION.SDK_INT >= 14) {
            f320b = new C0069g();
        } else {
            f320b = new C0068f();
        }
    }

    public void m462a(int i, int i2) {
        f320b.m468a(this.f321a, i, i2);
    }

    public boolean m463a() {
        return f320b.m469a(this.f321a);
    }

    public boolean m464a(float f) {
        return f320b.m470a(this.f321a, f);
    }

    public boolean m465a(Canvas canvas) {
        return f320b.m471a(this.f321a, canvas);
    }

    public void m466b() {
        f320b.m472b(this.f321a);
    }

    public boolean m467c() {
        return f320b.m473c(this.f321a);
    }
}
