package android.support.v4.p004h;

import android.view.View;
import android.view.ViewParent;

/* renamed from: android.support.v4.h.bj */
public class bj {
    private final View f436a;
    private ViewParent f437b;
    private boolean f438c;
    private int[] f439d;

    public bj(View view) {
        this.f436a = view;
    }

    public void m958a(boolean z) {
        if (this.f438c) {
            bu.m1007p(this.f436a);
        }
        this.f438c = z;
    }

    public boolean m959a() {
        return this.f438c;
    }

    public boolean m960a(float f, float f2) {
        return (!m959a() || this.f437b == null) ? false : da.m1186a(this.f437b, this.f436a, f, f2);
    }

    public boolean m961a(float f, float f2, boolean z) {
        return (!m959a() || this.f437b == null) ? false : da.m1187a(this.f437b, this.f436a, f, f2, z);
    }

    public boolean m962a(int i) {
        if (m965b()) {
            return true;
        }
        if (m959a()) {
            View view = this.f436a;
            for (ViewParent parent = this.f436a.getParent(); parent != null; parent = parent.getParent()) {
                if (da.m1188a(parent, view, this.f436a, i)) {
                    this.f437b = parent;
                    da.m1189b(parent, view, this.f436a, i);
                    return true;
                }
                if (parent instanceof View) {
                    view = (View) parent;
                }
            }
        }
        return false;
    }

    public boolean m963a(int i, int i2, int i3, int i4, int[] iArr) {
        if (!m959a() || this.f437b == null) {
            return false;
        }
        if (i != 0 || i2 != 0 || i3 != 0 || i4 != 0) {
            int i5;
            int i6;
            if (iArr != null) {
                this.f436a.getLocationInWindow(iArr);
                int i7 = iArr[0];
                i5 = iArr[1];
                i6 = i7;
            } else {
                i5 = 0;
                i6 = 0;
            }
            da.m1184a(this.f437b, this.f436a, i, i2, i3, i4);
            if (iArr != null) {
                this.f436a.getLocationInWindow(iArr);
                iArr[0] = iArr[0] - i6;
                iArr[1] = iArr[1] - i5;
            }
            return true;
        } else if (iArr == null) {
            return false;
        } else {
            iArr[0] = 0;
            iArr[1] = 0;
            return false;
        }
    }

    public boolean m964a(int i, int i2, int[] iArr, int[] iArr2) {
        if (!m959a() || this.f437b == null) {
            return false;
        }
        if (i != 0 || i2 != 0) {
            int i3;
            int i4;
            if (iArr2 != null) {
                this.f436a.getLocationInWindow(iArr2);
                i3 = iArr2[0];
                i4 = iArr2[1];
            } else {
                i4 = 0;
                i3 = 0;
            }
            if (iArr == null) {
                if (this.f439d == null) {
                    this.f439d = new int[2];
                }
                iArr = this.f439d;
            }
            iArr[0] = 0;
            iArr[1] = 0;
            da.m1185a(this.f437b, this.f436a, i, i2, iArr);
            if (iArr2 != null) {
                this.f436a.getLocationInWindow(iArr2);
                iArr2[0] = iArr2[0] - i3;
                iArr2[1] = iArr2[1] - i4;
            }
            return (iArr[0] == 0 && iArr[1] == 0) ? false : true;
        } else if (iArr2 == null) {
            return false;
        } else {
            iArr2[0] = 0;
            iArr2[1] = 0;
            return false;
        }
    }

    public boolean m965b() {
        return this.f437b != null;
    }

    public void m966c() {
        if (this.f437b != null) {
            da.m1183a(this.f437b, this.f436a);
            this.f437b = null;
        }
    }
}
