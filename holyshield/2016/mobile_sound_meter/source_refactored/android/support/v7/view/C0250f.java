package android.support.v7.view;

import android.content.Context;
import android.support.v7.view.menu.C0203j;
import android.support.v7.view.menu.C0264i;
import android.support.v7.widget.ActionBarContextView;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import java.lang.ref.WeakReference;

/* renamed from: android.support.v7.view.f */
public class C0250f extends C0212b implements C0203j {
    private Context f851a;
    private ActionBarContextView f852b;
    private C0208c f853c;
    private WeakReference f854d;
    private boolean f855e;
    private boolean f856f;
    private C0264i f857g;

    public C0250f(Context context, ActionBarContextView actionBarContextView, C0208c c0208c, boolean z) {
        this.f851a = context;
        this.f852b = actionBarContextView;
        this.f853c = c0208c;
        this.f857g = new C0264i(actionBarContextView.getContext()).m2101a(1);
        this.f857g.m2109a((C0203j) this);
        this.f856f = z;
    }

    public MenuInflater m2000a() {
        return new MenuInflater(this.f852b.getContext());
    }

    public void m2001a(int i) {
        m2009b(this.f851a.getString(i));
    }

    public void m2002a(C0264i c0264i) {
        m2011d();
        this.f852b.m2291a();
    }

    public void m2003a(View view) {
        this.f852b.setCustomView(view);
        this.f854d = view != null ? new WeakReference(view) : null;
    }

    public void m2004a(CharSequence charSequence) {
        this.f852b.setSubtitle(charSequence);
    }

    public void m2005a(boolean z) {
        super.m1882a(z);
        this.f852b.setTitleOptional(z);
    }

    public boolean m2006a(C0264i c0264i, MenuItem menuItem) {
        return this.f853c.m1760a((C0212b) this, menuItem);
    }

    public Menu m2007b() {
        return this.f857g;
    }

    public void m2008b(int i) {
        m2004a(this.f851a.getString(i));
    }

    public void m2009b(CharSequence charSequence) {
        this.f852b.setTitle(charSequence);
    }

    public void m2010c() {
        if (!this.f855e) {
            this.f855e = true;
            this.f852b.sendAccessibilityEvent(32);
            this.f853c.m1758a(this);
        }
    }

    public void m2011d() {
        this.f853c.m1761b(this, this.f857g);
    }

    public CharSequence m2012f() {
        return this.f852b.getTitle();
    }

    public CharSequence m2013g() {
        return this.f852b.getSubtitle();
    }

    public boolean m2014h() {
        return this.f852b.m2294d();
    }

    public View m2015i() {
        return this.f854d != null ? (View) this.f854d.get() : null;
    }
}
