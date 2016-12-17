package android.support.v4.p004h;

import android.view.WindowInsets;

/* renamed from: android.support.v4.h.ec */
class ec extends eb {
    private final WindowInsets f471a;

    ec(WindowInsets windowInsets) {
        this.f471a = windowInsets;
    }

    public int m1298a() {
        return this.f471a.getSystemWindowInsetLeft();
    }

    public eb m1299a(int i, int i2, int i3, int i4) {
        return new ec(this.f471a.replaceSystemWindowInsets(i, i2, i3, i4));
    }

    public int m1300b() {
        return this.f471a.getSystemWindowInsetTop();
    }

    public int m1301c() {
        return this.f471a.getSystemWindowInsetRight();
    }

    public int m1302d() {
        return this.f471a.getSystemWindowInsetBottom();
    }

    WindowInsets m1303e() {
        return this.f471a;
    }
}
