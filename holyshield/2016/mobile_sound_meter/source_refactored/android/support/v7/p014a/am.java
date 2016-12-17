package android.support.v7.p014a;

import android.support.v7.p015b.C0243l;
import android.support.v7.view.menu.C0207y;
import android.support.v7.view.menu.C0264i;
import android.view.Window.Callback;

/* renamed from: android.support.v7.a.am */
final class am implements C0207y {
    final /* synthetic */ ae f622a;

    private am(ae aeVar) {
        this.f622a = aeVar;
    }

    public void m1756a(C0264i c0264i, boolean z) {
        this.f622a.m1680b(c0264i);
    }

    public boolean m1757a(C0264i c0264i) {
        Callback o = this.f622a.m1658o();
        if (o != null) {
            o.onMenuOpened(C0243l.AppCompatTheme_ratingBarStyleSmall, c0264i);
        }
        return true;
    }
}
