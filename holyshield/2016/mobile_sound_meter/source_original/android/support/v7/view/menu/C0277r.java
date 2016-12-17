package android.support.v7.view.menu;

import android.support.v4.p004h.aw;
import android.view.MenuItem;
import android.view.MenuItem.OnActionExpandListener;

/* renamed from: android.support.v7.view.menu.r */
class C0277r extends C0262f implements aw {
    final /* synthetic */ C0274o f1051a;

    C0277r(C0274o c0274o, OnActionExpandListener onActionExpandListener) {
        this.f1051a = c0274o;
        super(onActionExpandListener);
    }

    public boolean m2249a(MenuItem menuItem) {
        return ((OnActionExpandListener) this.b).onMenuItemActionExpand(this.f1051a.m2087a(menuItem));
    }

    public boolean m2250b(MenuItem menuItem) {
        return ((OnActionExpandListener) this.b).onMenuItemActionCollapse(this.f1051a.m2087a(menuItem));
    }
}
