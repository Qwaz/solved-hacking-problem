package android.support.v7.p014a;

import android.support.v7.p015b.C0243l;
import android.support.v7.view.menu.C0207y;
import android.support.v7.view.menu.C0264i;
import android.view.Menu;
import android.view.Window.Callback;

/* renamed from: android.support.v7.a.ar */
final class ar implements C0207y {
    final /* synthetic */ ae f654a;

    private ar(ae aeVar) {
        this.f654a = aeVar;
    }

    public void m1774a(C0264i c0264i, boolean z) {
        Menu menu;
        Menu p = c0264i.m2142p();
        boolean z2 = p != c0264i;
        ae aeVar = this.f654a;
        if (z2) {
            menu = p;
        }
        aq a = aeVar.m1665a(menu);
        if (a == null) {
            return;
        }
        if (z2) {
            this.f654a.m1666a(a.f635a, a, p);
            this.f654a.m1672a(a, true);
            return;
        }
        this.f654a.m1672a(a, z);
    }

    public boolean m1775a(C0264i c0264i) {
        if (c0264i == null && this.f654a.h) {
            Callback o = this.f654a.m1658o();
            if (!(o == null || this.f654a.m1657n())) {
                o.onMenuOpened(C0243l.AppCompatTheme_ratingBarStyleSmall, c0264i);
            }
        }
        return true;
    }
}
