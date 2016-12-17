package android.support.v4.p004h;

import android.content.Context;
import android.util.Log;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;

/* renamed from: android.support.v4.h.n */
public abstract class C0161n {
    private final Context f476a;
    private C0162o f477b;
    private C0163p f478c;

    public C0161n(Context context) {
        this.f476a = context;
    }

    public abstract View m1334a();

    public View m1335a(MenuItem menuItem) {
        return m1334a();
    }

    public void m1336a(C0162o c0162o) {
        this.f477b = c0162o;
    }

    public void m1337a(C0163p c0163p) {
        if (!(this.f478c == null || c0163p == null)) {
            Log.w("ActionProvider(support)", "setVisibilityListener: Setting a new ActionProvider.VisibilityListener when one is already set. Are you reusing this " + getClass().getSimpleName() + " instance while it is still in use somewhere else?");
        }
        this.f478c = c0163p;
    }

    public void m1338a(SubMenu subMenu) {
    }

    public void m1339a(boolean z) {
        if (this.f477b != null) {
            this.f477b.m1345a(z);
        }
    }

    public boolean m1340b() {
        return false;
    }

    public boolean m1341c() {
        return true;
    }

    public boolean m1342d() {
        return false;
    }

    public boolean m1343e() {
        return false;
    }

    public void m1344f() {
        this.f478c = null;
        this.f477b = null;
    }
}
