package android.support.v7.view;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.Resources.Theme;
import android.support.v7.p015b.C0242k;
import android.view.LayoutInflater;

/* renamed from: android.support.v7.view.e */
public class C0249e extends ContextWrapper {
    private int f848a;
    private Theme f849b;
    private LayoutInflater f850c;

    public C0249e(Context context, int i) {
        super(context);
        this.f848a = i;
    }

    public C0249e(Context context, Theme theme) {
        super(context);
        this.f849b = theme;
    }

    private void m1997b() {
        boolean z = this.f849b == null;
        if (z) {
            this.f849b = getResources().newTheme();
            Theme theme = getBaseContext().getTheme();
            if (theme != null) {
                this.f849b.setTo(theme);
            }
        }
        m1999a(this.f849b, this.f848a, z);
    }

    public int m1998a() {
        return this.f848a;
    }

    protected void m1999a(Theme theme, int i, boolean z) {
        theme.applyStyle(i, true);
    }

    public Object getSystemService(String str) {
        if (!"layout_inflater".equals(str)) {
            return getBaseContext().getSystemService(str);
        }
        if (this.f850c == null) {
            this.f850c = LayoutInflater.from(getBaseContext()).cloneInContext(this);
        }
        return this.f850c;
    }

    public Theme getTheme() {
        if (this.f849b != null) {
            return this.f849b;
        }
        if (this.f848a == 0) {
            this.f848a = C0242k.Theme_AppCompat_Light;
        }
        m1997b();
        return this.f849b;
    }

    public void setTheme(int i) {
        if (this.f848a != i) {
            this.f848a = i;
            m1997b();
        }
    }
}
