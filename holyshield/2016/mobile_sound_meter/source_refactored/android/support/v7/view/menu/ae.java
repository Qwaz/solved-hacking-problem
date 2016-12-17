package android.support.v7.view.menu;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.support.v4.p008d.p009a.C0091c;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;

class ae extends ac implements SubMenu {
    ae(Context context, C0091c c0091c) {
        super(context, c0091c);
    }

    public C0091c m2154b() {
        return (C0091c) this.b;
    }

    public void clearHeader() {
        m2154b().clearHeader();
    }

    public MenuItem getItem() {
        return m2087a(m2154b().getItem());
    }

    public SubMenu setHeaderIcon(int i) {
        m2154b().setHeaderIcon(i);
        return this;
    }

    public SubMenu setHeaderIcon(Drawable drawable) {
        m2154b().setHeaderIcon(drawable);
        return this;
    }

    public SubMenu setHeaderTitle(int i) {
        m2154b().setHeaderTitle(i);
        return this;
    }

    public SubMenu setHeaderTitle(CharSequence charSequence) {
        m2154b().setHeaderTitle(charSequence);
        return this;
    }

    public SubMenu setHeaderView(View view) {
        m2154b().setHeaderView(view);
        return this;
    }

    public SubMenu setIcon(int i) {
        m2154b().setIcon(i);
        return this;
    }

    public SubMenu setIcon(Drawable drawable) {
        m2154b().setIcon(drawable);
        return this;
    }
}
