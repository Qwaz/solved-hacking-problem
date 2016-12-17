package android.support.v7.view.menu;

import android.content.Context;
import android.support.v4.p004h.C0163p;
import android.view.ActionProvider;
import android.view.ActionProvider.VisibilityListener;
import android.view.MenuItem;
import android.view.View;

/* renamed from: android.support.v7.view.menu.u */
class C0280u extends C0275p implements VisibilityListener {
    C0163p f1053c;
    final /* synthetic */ C0279t f1054d;

    public C0280u(C0279t c0279t, Context context, ActionProvider actionProvider) {
        this.f1054d = c0279t;
        super(c0279t, context, actionProvider);
    }

    public View m2252a(MenuItem menuItem) {
        return this.a.onCreateActionView(menuItem);
    }

    public void m2253a(C0163p c0163p) {
        VisibilityListener visibilityListener;
        this.f1053c = c0163p;
        ActionProvider actionProvider = this.a;
        if (c0163p == null) {
            visibilityListener = null;
        }
        actionProvider.setVisibilityListener(visibilityListener);
    }

    public boolean m2254b() {
        return this.a.overridesItemVisibility();
    }

    public boolean m2255c() {
        return this.a.isVisible();
    }

    public void onActionProviderVisibilityChanged(boolean z) {
        if (this.f1053c != null) {
            this.f1053c.m1346a(z);
        }
    }
}
