package android.support.v7.view.menu;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.support.v4.p002b.C0020a;
import android.view.Menu;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;

public class ad extends C0264i implements SubMenu {
    private C0264i f982d;
    private C0272m f983e;

    public ad(Context context, C0264i c0264i, C0272m c0272m) {
        super(context);
        this.f982d = c0264i;
        this.f983e = c0272m;
    }

    public String m2145a() {
        int itemId = this.f983e != null ? this.f983e.getItemId() : 0;
        return itemId == 0 ? null : super.m2107a() + ":" + itemId;
    }

    public void m2146a(C0203j c0203j) {
        this.f982d.m2109a(c0203j);
    }

    boolean m2147a(C0264i c0264i, MenuItem menuItem) {
        return super.m2116a(c0264i, menuItem) || this.f982d.m2116a(c0264i, menuItem);
    }

    public boolean m2148b() {
        return this.f982d.m2124b();
    }

    public boolean m2149c() {
        return this.f982d.m2127c();
    }

    public boolean m2150c(C0272m c0272m) {
        return this.f982d.m2128c(c0272m);
    }

    public boolean m2151d(C0272m c0272m) {
        return this.f982d.m2130d(c0272m);
    }

    public MenuItem getItem() {
        return this.f983e;
    }

    public C0264i m2152p() {
        return this.f982d;
    }

    public Menu m2153s() {
        return this.f982d;
    }

    public SubMenu setHeaderIcon(int i) {
        super.m2102a(C0020a.m74a(m2131e(), i));
        return this;
    }

    public SubMenu setHeaderIcon(Drawable drawable) {
        super.m2102a(drawable);
        return this;
    }

    public SubMenu setHeaderTitle(int i) {
        super.m2104a(m2131e().getResources().getString(i));
        return this;
    }

    public SubMenu setHeaderTitle(CharSequence charSequence) {
        super.m2104a(charSequence);
        return this;
    }

    public SubMenu setHeaderView(View view) {
        super.m2103a(view);
        return this;
    }

    public SubMenu setIcon(int i) {
        this.f983e.setIcon(i);
        return this;
    }

    public SubMenu setIcon(Drawable drawable) {
        this.f983e.setIcon(drawable);
        return this;
    }

    public void setQwertyMode(boolean z) {
        this.f982d.setQwertyMode(z);
    }
}
