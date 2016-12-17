package android.support.v7.view.menu;

import android.content.Context;
import android.support.v4.p004h.C0161n;
import android.view.ActionProvider;
import android.view.SubMenu;
import android.view.View;

/* renamed from: android.support.v7.view.menu.p */
class C0275p extends C0161n {
    final ActionProvider f1048a;
    final /* synthetic */ C0274o f1049b;

    public C0275p(C0274o c0274o, Context context, ActionProvider actionProvider) {
        this.f1049b = c0274o;
        super(context);
        this.f1048a = actionProvider;
    }

    public View m2242a() {
        return this.f1048a.onCreateActionView();
    }

    public void m2243a(SubMenu subMenu) {
        this.f1048a.onPrepareSubMenu(this.f1049b.m2088a(subMenu));
    }

    public boolean m2244d() {
        return this.f1048a.onPerformDefaultAction();
    }

    public boolean m2245e() {
        return this.f1048a.hasSubMenu();
    }
}
