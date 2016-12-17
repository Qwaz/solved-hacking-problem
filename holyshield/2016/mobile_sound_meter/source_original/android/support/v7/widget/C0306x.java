package android.support.v7.widget;

import android.support.v7.view.menu.C0203j;
import android.support.v7.view.menu.C0264i;
import android.view.MenuItem;

/* renamed from: android.support.v7.widget.x */
class C0306x implements C0203j {
    final /* synthetic */ ActionMenuView f1600a;

    private C0306x(ActionMenuView actionMenuView) {
        this.f1600a = actionMenuView;
    }

    public void m2844a(C0264i c0264i) {
        if (this.f1600a.f1154g != null) {
            this.f1600a.f1154g.m1660a(c0264i);
        }
    }

    public boolean m2845a(C0264i c0264i, MenuItem menuItem) {
        return this.f1600a.f1159l != null && this.f1600a.f1159l.m2727a(menuItem);
    }
}
