package android.support.v4.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.os.Build.VERSION;

/* renamed from: android.support.v4.widget.s */
public final class C0192s {
    private static final C0193v f563b;
    private Object f564a;

    static {
        if (VERSION.SDK_INT >= 21) {
            f563b = new C0196w();
        } else if (VERSION.SDK_INT >= 14) {
            f563b = new C0195u();
        } else {
            f563b = new C0194t();
        }
    }

    public C0192s(Context context) {
        this.f564a = f563b.m1566a(context);
    }

    public void m1560a(int i, int i2) {
        f563b.m1567a(this.f564a, i, i2);
    }

    public boolean m1561a() {
        return f563b.m1568a(this.f564a);
    }

    public boolean m1562a(float f, float f2) {
        return f563b.m1569a(this.f564a, f, f2);
    }

    public boolean m1563a(int i) {
        return f563b.m1570a(this.f564a, i);
    }

    public boolean m1564a(Canvas canvas) {
        return f563b.m1571a(this.f564a, canvas);
    }

    public boolean m1565b() {
        return f563b.m1572b(this.f564a);
    }
}
