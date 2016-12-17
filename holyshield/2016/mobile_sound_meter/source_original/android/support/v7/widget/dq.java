package android.support.v7.widget;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.bu;
import android.support.v4.p004h.dh;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0237f;
import android.support.v7.p015b.C0238g;
import android.support.v7.p015b.C0241j;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.menu.C0203j;
import android.support.v7.view.menu.C0207y;
import android.support.v7.view.menu.C0264i;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.Window.Callback;

public class dq implements bs {
    private Toolbar f1532a;
    private int f1533b;
    private View f1534c;
    private View f1535d;
    private Drawable f1536e;
    private Drawable f1537f;
    private Drawable f1538g;
    private boolean f1539h;
    private CharSequence f1540i;
    private CharSequence f1541j;
    private CharSequence f1542k;
    private Callback f1543l;
    private boolean f1544m;
    private C0294k f1545n;
    private int f1546o;
    private final ao f1547p;
    private int f1548q;
    private Drawable f1549r;

    public dq(Toolbar toolbar, boolean z) {
        this(toolbar, z, C0241j.abc_action_bar_up_description, C0237f.abc_ic_ab_back_mtrl_am_alpha);
    }

    public dq(Toolbar toolbar, boolean z, int i, int i2) {
        this.f1546o = 0;
        this.f1548q = 0;
        this.f1532a = toolbar;
        this.f1540i = toolbar.getTitle();
        this.f1541j = toolbar.getSubtitle();
        this.f1539h = this.f1540i != null;
        this.f1538g = toolbar.getNavigationIcon();
        if (z) {
            dh a = dh.m2710a(toolbar.getContext(), null, C0243l.ActionBar, C0233b.actionBarStyle, 0);
            CharSequence c = a.m2719c(C0243l.ActionBar_title);
            if (!TextUtils.isEmpty(c)) {
                m2763b(c);
            }
            c = a.m2719c(C0243l.ActionBar_subtitle);
            if (!TextUtils.isEmpty(c)) {
                m2767c(c);
            }
            Drawable a2 = a.m2713a(C0243l.ActionBar_logo);
            if (a2 != null) {
                m2766c(a2);
            }
            a2 = a.m2713a(C0243l.ActionBar_icon);
            if (this.f1538g == null && a2 != null) {
                m2752a(a2);
            }
            a2 = a.m2713a(C0243l.ActionBar_homeAsUpIndicator);
            if (a2 != null) {
                m2771d(a2);
            }
            m2765c(a.m2712a(C0243l.ActionBar_displayOptions, 0));
            int g = a.m2726g(C0243l.ActionBar_customNavigationLayout, 0);
            if (g != 0) {
                m2756a(LayoutInflater.from(this.f1532a.getContext()).inflate(g, this.f1532a, false));
                m2765c(this.f1533b | 16);
            }
            g = a.m2724f(C0243l.ActionBar_height, 0);
            if (g > 0) {
                LayoutParams layoutParams = this.f1532a.getLayoutParams();
                layoutParams.height = g;
                this.f1532a.setLayoutParams(layoutParams);
            }
            g = a.m2720d(C0243l.ActionBar_contentInsetStart, -1);
            int d = a.m2720d(C0243l.ActionBar_contentInsetEnd, -1);
            if (g >= 0 || d >= 0) {
                this.f1532a.m2441a(Math.max(g, 0), Math.max(d, 0));
            }
            g = a.m2726g(C0243l.ActionBar_titleTextStyle, 0);
            if (g != 0) {
                this.f1532a.m2442a(this.f1532a.getContext(), g);
            }
            g = a.m2726g(C0243l.ActionBar_subtitleTextStyle, 0);
            if (g != 0) {
                this.f1532a.m2446b(this.f1532a.getContext(), g);
            }
            int g2 = a.m2726g(C0243l.ActionBar_popupTheme, 0);
            if (g2 != 0) {
                this.f1532a.setPopupTheme(g2);
            }
            a.m2714a();
        } else {
            this.f1533b = m2745s();
        }
        this.f1547p = ao.m2497a();
        m2770d(i);
        this.f1542k = this.f1532a.getNavigationContentDescription();
        m2762b(this.f1547p.m2520a(m2760b(), i2));
        this.f1532a.setNavigationOnClickListener(new dr(this));
    }

    private void m2744e(CharSequence charSequence) {
        this.f1540i = charSequence;
        if ((this.f1533b & 8) != 0) {
            this.f1532a.setTitle(charSequence);
        }
    }

    private int m2745s() {
        return this.f1532a.getNavigationIcon() != null ? 15 : 11;
    }

    private void m2746t() {
        Drawable drawable = null;
        if ((this.f1533b & 2) != 0) {
            drawable = (this.f1533b & 1) != 0 ? this.f1537f != null ? this.f1537f : this.f1536e : this.f1536e;
        }
        this.f1532a.setLogo(drawable);
    }

    private void m2747u() {
        if ((this.f1533b & 4) == 0) {
            return;
        }
        if (TextUtils.isEmpty(this.f1542k)) {
            this.f1532a.setNavigationContentDescription(this.f1548q);
        } else {
            this.f1532a.setNavigationContentDescription(this.f1542k);
        }
    }

    private void m2748v() {
        if ((this.f1533b & 4) != 0) {
            this.f1532a.setNavigationIcon(this.f1538g != null ? this.f1538g : this.f1549r);
        }
    }

    public dh m2749a(int i, long j) {
        return bu.m1000i(this.f1532a).m1225a(i == 0 ? 1.0f : 0.0f).m1226a(j).m1227a(new ds(this, i));
    }

    public ViewGroup m2750a() {
        return this.f1532a;
    }

    public void m2751a(int i) {
        m2752a(i != 0 ? this.f1547p.m2520a(m2760b(), i) : null);
    }

    public void m2752a(Drawable drawable) {
        this.f1536e = drawable;
        m2746t();
    }

    public void m2753a(C0207y c0207y, C0203j c0203j) {
        this.f1532a.m2444a(c0207y, c0203j);
    }

    public void m2754a(cp cpVar) {
        if (this.f1534c != null && this.f1534c.getParent() == this.f1532a) {
            this.f1532a.removeView(this.f1534c);
        }
        this.f1534c = cpVar;
        if (cpVar != null && this.f1546o == 2) {
            this.f1532a.addView(this.f1534c, 0);
            dm dmVar = (dm) this.f1534c.getLayoutParams();
            dmVar.width = -2;
            dmVar.height = -2;
            dmVar.a = 8388691;
            cpVar.setAllowCollapse(true);
        }
    }

    public void m2755a(Menu menu, C0207y c0207y) {
        if (this.f1545n == null) {
            this.f1545n = new C0294k(this.f1532a.getContext());
            this.f1545n.m2180a(C0238g.action_menu_presenter);
        }
        this.f1545n.m2184a(c0207y);
        this.f1532a.m2443a((C0264i) menu, this.f1545n);
    }

    public void m2756a(View view) {
        if (!(this.f1535d == null || (this.f1533b & 16) == 0)) {
            this.f1532a.removeView(this.f1535d);
        }
        this.f1535d = view;
        if (view != null && (this.f1533b & 16) != 0) {
            this.f1532a.addView(this.f1535d);
        }
    }

    public void m2757a(Callback callback) {
        this.f1543l = callback;
    }

    public void m2758a(CharSequence charSequence) {
        if (!this.f1539h) {
            m2744e(charSequence);
        }
    }

    public void m2759a(boolean z) {
        this.f1532a.setCollapsible(z);
    }

    public Context m2760b() {
        return this.f1532a.getContext();
    }

    public void m2761b(int i) {
        m2766c(i != 0 ? this.f1547p.m2520a(m2760b(), i) : null);
    }

    public void m2762b(Drawable drawable) {
        if (this.f1549r != drawable) {
            this.f1549r = drawable;
            m2748v();
        }
    }

    public void m2763b(CharSequence charSequence) {
        this.f1539h = true;
        m2744e(charSequence);
    }

    public void m2764b(boolean z) {
    }

    public void m2765c(int i) {
        int i2 = this.f1533b ^ i;
        this.f1533b = i;
        if (i2 != 0) {
            if ((i2 & 4) != 0) {
                if ((i & 4) != 0) {
                    m2748v();
                    m2747u();
                } else {
                    this.f1532a.setNavigationIcon(null);
                }
            }
            if ((i2 & 3) != 0) {
                m2746t();
            }
            if ((i2 & 8) != 0) {
                if ((i & 8) != 0) {
                    this.f1532a.setTitle(this.f1540i);
                    this.f1532a.setSubtitle(this.f1541j);
                } else {
                    this.f1532a.setTitle(null);
                    this.f1532a.setSubtitle(null);
                }
            }
            if ((i2 & 16) != 0 && this.f1535d != null) {
                if ((i & 16) != 0) {
                    this.f1532a.addView(this.f1535d);
                } else {
                    this.f1532a.removeView(this.f1535d);
                }
            }
        }
    }

    public void m2766c(Drawable drawable) {
        this.f1537f = drawable;
        m2746t();
    }

    public void m2767c(CharSequence charSequence) {
        this.f1541j = charSequence;
        if ((this.f1533b & 8) != 0) {
            this.f1532a.setSubtitle(charSequence);
        }
    }

    public boolean m2768c() {
        return this.f1532a.m2452g();
    }

    public void m2769d() {
        this.f1532a.m2453h();
    }

    public void m2770d(int i) {
        if (i != this.f1548q) {
            this.f1548q = i;
            if (TextUtils.isEmpty(this.f1532a.getNavigationContentDescription())) {
                m2774e(this.f1548q);
            }
        }
    }

    public void m2771d(Drawable drawable) {
        this.f1538g = drawable;
        m2748v();
    }

    public void m2772d(CharSequence charSequence) {
        this.f1542k = charSequence;
        m2747u();
    }

    public CharSequence m2773e() {
        return this.f1532a.getTitle();
    }

    public void m2774e(int i) {
        m2772d(i == 0 ? null : m2760b().getString(i));
    }

    public void m2775f() {
        Log.i("ToolbarWidgetWrapper", "Progress display unsupported");
    }

    public void m2776g() {
        Log.i("ToolbarWidgetWrapper", "Progress display unsupported");
    }

    public boolean m2777h() {
        return this.f1532a.m2445a();
    }

    public boolean m2778i() {
        return this.f1532a.m2447b();
    }

    public boolean m2779j() {
        return this.f1532a.m2448c();
    }

    public boolean m2780k() {
        return this.f1532a.m2449d();
    }

    public boolean m2781l() {
        return this.f1532a.m2450e();
    }

    public void m2782m() {
        this.f1544m = true;
    }

    public void m2783n() {
        this.f1532a.m2451f();
    }

    public int m2784o() {
        return this.f1533b;
    }

    public int m2785p() {
        return this.f1546o;
    }

    public int m2786q() {
        return this.f1532a.getVisibility();
    }

    public Menu m2787r() {
        return this.f1532a.getMenu();
    }
}
