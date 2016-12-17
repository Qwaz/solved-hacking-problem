package android.support.v7.p014a;

import android.support.v4.p004h.bu;
import android.support.v7.view.C0208c;
import android.support.v7.view.C0212b;
import android.view.Menu;
import android.view.MenuItem;

/* renamed from: android.support.v7.a.an */
class an implements C0208c {
    final /* synthetic */ ae f623a;
    private C0208c f624b;

    public an(ae aeVar, C0208c c0208c) {
        this.f623a = aeVar;
        this.f624b = c0208c;
    }

    public void m1762a(C0212b c0212b) {
        this.f624b.m1758a(c0212b);
        if (this.f623a.f594o != null) {
            this.f623a.b.getDecorView().removeCallbacks(this.f623a.f595p);
        }
        if (this.f623a.f593n != null) {
            this.f623a.m1697u();
            this.f623a.f596q = bu.m1000i(this.f623a.f593n).m1225a(0.0f);
            this.f623a.f596q.m1227a(new ao(this));
        }
        if (this.f623a.e != null) {
            this.f623a.e.m1778b(this.f623a.f592m);
        }
        this.f623a.f592m = null;
    }

    public boolean m1763a(C0212b c0212b, Menu menu) {
        return this.f624b.m1759a(c0212b, menu);
    }

    public boolean m1764a(C0212b c0212b, MenuItem menuItem) {
        return this.f624b.m1760a(c0212b, menuItem);
    }

    public boolean m1765b(C0212b c0212b, Menu menu) {
        return this.f624b.m1761b(c0212b, menu);
    }
}
