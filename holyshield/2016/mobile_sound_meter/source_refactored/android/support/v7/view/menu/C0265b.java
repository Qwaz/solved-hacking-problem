package android.support.v7.view.menu;

import android.support.v7.widget.by;
import android.support.v7.widget.cd;

/* renamed from: android.support.v7.view.menu.b */
class C0265b extends cd {
    final /* synthetic */ ActionMenuItemView f994a;

    public C0265b(ActionMenuItemView actionMenuItemView) {
        this.f994a = actionMenuItemView;
        super(actionMenuItemView);
    }

    public by m2167a() {
        return this.f994a.f916f != null ? this.f994a.f916f.m2169a() : null;
    }

    protected boolean m2168b() {
        if (this.f994a.f914d == null || !this.f994a.f914d.m2068a(this.f994a.f911a)) {
            return false;
        }
        by a = m2167a();
        return a != null && a.m2581k();
    }
}
