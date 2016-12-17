package android.support.v7.widget;

import android.content.Context;
import android.support.v7.view.C0248d;
import android.support.v7.view.menu.C0264i;
import android.support.v7.view.menu.C0267x;
import android.support.v7.view.menu.C0272m;
import android.support.v7.view.menu.ad;
import android.view.ViewGroup.LayoutParams;

class dl implements C0267x {
    C0264i f1526a;
    C0272m f1527b;
    final /* synthetic */ Toolbar f1528c;

    private dl(Toolbar toolbar) {
        this.f1528c = toolbar;
    }

    public void m2729a(Context context, C0264i c0264i) {
        if (!(this.f1526a == null || this.f1527b == null)) {
            this.f1526a.m2130d(this.f1527b);
        }
        this.f1526a = c0264i;
    }

    public void m2730a(C0264i c0264i, boolean z) {
    }

    public boolean m2731a(ad adVar) {
        return false;
    }

    public boolean m2732a(C0264i c0264i, C0272m c0272m) {
        this.f1528c.m2436p();
        if (this.f1528c.f1248i.getParent() != this.f1528c) {
            this.f1528c.addView(this.f1528c.f1248i);
        }
        this.f1528c.f1240a = c0272m.getActionView();
        this.f1527b = c0272m;
        if (this.f1528c.f1240a.getParent() != this.f1528c) {
            LayoutParams i = this.f1528c.m2454i();
            i.a = 8388611 | (this.f1528c.f1253n & 112);
            i.f1529b = 2;
            this.f1528c.f1240a.setLayoutParams(i);
            this.f1528c.addView(this.f1528c.f1240a);
        }
        this.f1528c.m2455j();
        this.f1528c.requestLayout();
        c0272m.m2229e(true);
        if (this.f1528c.f1240a instanceof C0248d) {
            ((C0248d) this.f1528c.f1240a).m1995a();
        }
        return true;
    }

    public void m2733b(boolean z) {
        Object obj = null;
        if (this.f1527b != null) {
            if (this.f1526a != null) {
                int size = this.f1526a.size();
                for (int i = 0; i < size; i++) {
                    if (this.f1526a.getItem(i) == this.f1527b) {
                        obj = 1;
                        break;
                    }
                }
            }
            if (obj == null) {
                m2735b(this.f1526a, this.f1527b);
            }
        }
    }

    public boolean m2734b() {
        return false;
    }

    public boolean m2735b(C0264i c0264i, C0272m c0272m) {
        if (this.f1528c.f1240a instanceof C0248d) {
            ((C0248d) this.f1528c.f1240a).m1996b();
        }
        this.f1528c.removeView(this.f1528c.f1240a);
        this.f1528c.removeView(this.f1528c.f1248i);
        this.f1528c.f1240a = null;
        this.f1528c.m2456k();
        this.f1527b = null;
        this.f1528c.requestLayout();
        c0272m.m2229e(false);
        return true;
    }
}
