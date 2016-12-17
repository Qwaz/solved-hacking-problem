package android.support.v7.view.menu;

import android.view.MenuItem;
import android.view.MenuItem.OnMenuItemClickListener;

/* renamed from: android.support.v7.view.menu.s */
class C0278s extends C0262f implements OnMenuItemClickListener {
    final /* synthetic */ C0274o f1052a;

    C0278s(C0274o c0274o, OnMenuItemClickListener onMenuItemClickListener) {
        this.f1052a = c0274o;
        super(onMenuItemClickListener);
    }

    public boolean onMenuItemClick(MenuItem menuItem) {
        return ((OnMenuItemClickListener) this.b).onMenuItemClick(this.f1052a.m2087a(menuItem));
    }
}
