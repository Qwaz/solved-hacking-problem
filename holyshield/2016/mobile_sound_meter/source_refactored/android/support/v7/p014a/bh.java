package android.support.v7.p014a;

import android.content.Context;
import android.support.v7.view.C0208c;
import android.support.v7.view.C0212b;
import android.support.v7.view.C0253i;
import android.support.v7.view.menu.C0203j;
import android.support.v7.view.menu.C0264i;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import java.lang.ref.WeakReference;

/* renamed from: android.support.v7.a.bh */
public class bh extends C0212b implements C0203j {
    final /* synthetic */ bd f729a;
    private final Context f730b;
    private final C0264i f731c;
    private C0208c f732d;
    private WeakReference f733e;

    public bh(bd bdVar, Context context, C0208c c0208c) {
        this.f729a = bdVar;
        this.f730b = context;
        this.f732d = c0208c;
        this.f731c = new C0264i(context).m2101a(1);
        this.f731c.m2109a((C0203j) this);
    }

    public MenuInflater m1894a() {
        return new C0253i(this.f730b);
    }

    public void m1895a(int i) {
        m1903b(this.f729a.f709l.getResources().getString(i));
    }

    public void m1896a(C0264i c0264i) {
        if (this.f732d != null) {
            m1905d();
            this.f729a.f716s.m2291a();
        }
    }

    public void m1897a(View view) {
        this.f729a.f716s.setCustomView(view);
        this.f733e = new WeakReference(view);
    }

    public void m1898a(CharSequence charSequence) {
        this.f729a.f716s.setSubtitle(charSequence);
    }

    public void m1899a(boolean z) {
        super.m1882a(z);
        this.f729a.f716s.setTitleOptional(z);
    }

    public boolean m1900a(C0264i c0264i, MenuItem menuItem) {
        return this.f732d != null ? this.f732d.m1760a((C0212b) this, menuItem) : false;
    }

    public Menu m1901b() {
        return this.f731c;
    }

    public void m1902b(int i) {
        m1898a(this.f729a.f709l.getResources().getString(i));
    }

    public void m1903b(CharSequence charSequence) {
        this.f729a.f716s.setTitle(charSequence);
    }

    public void m1904c() {
        if (this.f729a.f702a == this) {
            if (bd.m1833b(this.f729a.f696D, this.f729a.f697E, false)) {
                this.f732d.m1758a(this);
            } else {
                this.f729a.f703b = this;
                this.f729a.f704c = this.f732d;
            }
            this.f732d = null;
            this.f729a.m1868j(false);
            this.f729a.f716s.m2292b();
            this.f729a.f715r.m2603a().sendAccessibilityEvent(32);
            this.f729a.f713p.setHideOnContentScrollEnabled(this.f729a.f705d);
            this.f729a.f702a = null;
        }
    }

    public void m1905d() {
        if (this.f729a.f702a == this) {
            this.f731c.m2133g();
            try {
                this.f732d.m1761b(this, this.f731c);
            } finally {
                this.f731c.m2134h();
            }
        }
    }

    public boolean m1906e() {
        this.f731c.m2133g();
        try {
            boolean a = this.f732d.m1759a((C0212b) this, this.f731c);
            return a;
        } finally {
            this.f731c.m2134h();
        }
    }

    public CharSequence m1907f() {
        return this.f729a.f716s.getTitle();
    }

    public CharSequence m1908g() {
        return this.f729a.f716s.getSubtitle();
    }

    public boolean m1909h() {
        return this.f729a.f716s.m2294d();
    }

    public View m1910i() {
        return this.f733e != null ? (View) this.f733e.get() : null;
    }
}
