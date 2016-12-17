package android.support.v7.p014a;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.support.v7.view.C0208c;
import android.support.v7.view.C0212b;
import android.support.v7.view.C0253i;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.Window;
import android.view.Window.Callback;

/* renamed from: android.support.v7.a.x */
abstract class C0202x extends C0201w {
    final Context f567a;
    final Window f568b;
    final Callback f569c;
    final Callback f570d;
    final C0209v f571e;
    C0200a f572f;
    MenuInflater f573g;
    boolean f574h;
    boolean f575i;
    boolean f576j;
    boolean f577k;
    boolean f578l;
    private CharSequence f579m;
    private boolean f580n;

    C0202x(Context context, Window window, C0209v c0209v) {
        this.f567a = context;
        this.f568b = window;
        this.f571e = c0209v;
        this.f569c = this.f568b.getCallback();
        if (this.f569c instanceof C0206y) {
            throw new IllegalStateException("AppCompat has already installed itself into the Window");
        }
        this.f570d = m1642a(this.f569c);
        this.f568b.setCallback(this.f570d);
    }

    public C0200a m1640a() {
        m1653j();
        return this.f572f;
    }

    abstract C0212b m1641a(C0208c c0208c);

    Callback m1642a(Callback callback) {
        return new C0206y(this, callback);
    }

    abstract void m1643a(int i, Menu menu);

    public final void m1644a(CharSequence charSequence) {
        this.f579m = charSequence;
        m1648b(charSequence);
    }

    abstract boolean m1645a(int i, KeyEvent keyEvent);

    abstract boolean m1646a(KeyEvent keyEvent);

    public MenuInflater m1647b() {
        if (this.f573g == null) {
            m1653j();
            this.f573g = new C0253i(this.f572f != null ? this.f572f.m1608c() : this.f567a);
        }
        return this.f573g;
    }

    abstract void m1648b(CharSequence charSequence);

    abstract boolean m1649b(int i, Menu menu);

    public void m1650c(Bundle bundle) {
    }

    public void m1651f() {
        this.f580n = true;
    }

    public boolean m1652h() {
        return false;
    }

    abstract void m1653j();

    final C0200a m1654k() {
        return this.f572f;
    }

    final Context m1655l() {
        Context context = null;
        C0200a a = m1640a();
        if (a != null) {
            context = a.m1608c();
        }
        return context == null ? this.f567a : context;
    }

    public boolean m1656m() {
        return false;
    }

    final boolean m1657n() {
        return this.f580n;
    }

    final Callback m1658o() {
        return this.f568b.getCallback();
    }

    final CharSequence m1659p() {
        return this.f569c instanceof Activity ? ((Activity) this.f569c).getTitle() : this.f579m;
    }
}
