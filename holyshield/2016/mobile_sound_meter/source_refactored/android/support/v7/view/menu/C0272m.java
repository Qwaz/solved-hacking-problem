package android.support.v7.view.menu;

import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v4.p004h.C0161n;
import android.support.v4.p004h.aw;
import android.support.v4.p008d.p009a.C0090b;
import android.support.v7.p015b.C0243l;
import android.support.v7.widget.ao;
import android.util.Log;
import android.view.ActionProvider;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.MenuItem.OnActionExpandListener;
import android.view.MenuItem.OnMenuItemClickListener;
import android.view.SubMenu;
import android.view.View;
import android.view.ViewDebug.CapturedViewProperty;
import android.widget.LinearLayout;

/* renamed from: android.support.v7.view.menu.m */
public final class C0272m implements C0090b {
    private static String f1020w;
    private static String f1021x;
    private static String f1022y;
    private static String f1023z;
    private final int f1024a;
    private final int f1025b;
    private final int f1026c;
    private final int f1027d;
    private CharSequence f1028e;
    private CharSequence f1029f;
    private Intent f1030g;
    private char f1031h;
    private char f1032i;
    private Drawable f1033j;
    private int f1034k;
    private C0264i f1035l;
    private ad f1036m;
    private Runnable f1037n;
    private OnMenuItemClickListener f1038o;
    private int f1039p;
    private int f1040q;
    private View f1041r;
    private C0161n f1042s;
    private aw f1043t;
    private boolean f1044u;
    private ContextMenuInfo f1045v;

    C0272m(C0264i c0264i, int i, int i2, int i3, int i4, CharSequence charSequence, int i5) {
        this.f1034k = 0;
        this.f1039p = 16;
        this.f1040q = 0;
        this.f1044u = false;
        this.f1035l = c0264i;
        this.f1024a = i2;
        this.f1025b = i;
        this.f1026c = i3;
        this.f1027d = i4;
        this.f1028e = charSequence;
        this.f1040q = i5;
    }

    public C0090b m2212a(int i) {
        Context e = this.f1035l.m2131e();
        m2215a(LayoutInflater.from(e).inflate(i, new LinearLayout(e), false));
        return this;
    }

    public C0090b m2213a(aw awVar) {
        this.f1043t = awVar;
        return this;
    }

    public C0090b m2214a(C0161n c0161n) {
        if (this.f1042s != null) {
            this.f1042s.m1344f();
        }
        this.f1041r = null;
        this.f1042s = c0161n;
        this.f1035l.m2123b(true);
        if (this.f1042s != null) {
            this.f1042s.m1337a(new C0273n(this));
        }
        return this;
    }

    public C0090b m2215a(View view) {
        this.f1041r = view;
        this.f1042s = null;
        if (view != null && view.getId() == -1 && this.f1024a > 0) {
            view.setId(this.f1024a);
        }
        this.f1035l.m2121b(this);
        return this;
    }

    public C0161n m2216a() {
        return this.f1042s;
    }

    CharSequence m2217a(aa aaVar) {
        return (aaVar == null || !aaVar.m2056a()) ? getTitle() : getTitleCondensed();
    }

    public void m2218a(ad adVar) {
        this.f1036m = adVar;
        adVar.setHeaderTitle(getTitle());
    }

    void m2219a(ContextMenuInfo contextMenuInfo) {
        this.f1045v = contextMenuInfo;
    }

    public void m2220a(boolean z) {
        this.f1039p = (z ? 4 : 0) | (this.f1039p & -5);
    }

    public C0090b m2221b(int i) {
        setShowAsAction(i);
        return this;
    }

    void m2222b(boolean z) {
        int i = this.f1039p;
        this.f1039p = (z ? 2 : 0) | (this.f1039p & -3);
        if (i != this.f1039p) {
            this.f1035l.m2123b(false);
        }
    }

    public boolean m2223b() {
        if ((this.f1038o != null && this.f1038o.onMenuItemClick(this)) || this.f1035l.m2116a(this.f1035l.m2142p(), (MenuItem) this)) {
            return true;
        }
        if (this.f1037n != null) {
            this.f1037n.run();
            return true;
        }
        if (this.f1030g != null) {
            try {
                this.f1035l.m2131e().startActivity(this.f1030g);
                return true;
            } catch (Throwable e) {
                Log.e("MenuItemImpl", "Can't find activity to handle intent; ignoring", e);
            }
        }
        return this.f1042s != null && this.f1042s.m1342d();
    }

    public int m2224c() {
        return this.f1027d;
    }

    boolean m2225c(boolean z) {
        int i = this.f1039p;
        this.f1039p = (z ? 0 : 8) | (this.f1039p & -9);
        return i != this.f1039p;
    }

    public boolean collapseActionView() {
        return (this.f1040q & 8) == 0 ? false : this.f1041r == null ? true : (this.f1043t == null || this.f1043t.m888b(this)) ? this.f1035l.m2130d(this) : false;
    }

    char m2226d() {
        return this.f1035l.m2124b() ? this.f1032i : this.f1031h;
    }

    public void m2227d(boolean z) {
        if (z) {
            this.f1039p |= 32;
        } else {
            this.f1039p &= -33;
        }
    }

    String m2228e() {
        char d = m2226d();
        if (d == '\u0000') {
            return "";
        }
        StringBuilder stringBuilder = new StringBuilder(f1020w);
        switch (d) {
            case C0243l.Toolbar_contentInsetRight /*8*/:
                stringBuilder.append(f1022y);
                break;
            case C0243l.Toolbar_titleTextAppearance /*10*/:
                stringBuilder.append(f1021x);
                break;
            case C0243l.AppCompatTheme_actionModeCutDrawable /*32*/:
                stringBuilder.append(f1023z);
                break;
            default:
                stringBuilder.append(d);
                break;
        }
        return stringBuilder.toString();
    }

    public void m2229e(boolean z) {
        this.f1044u = z;
        this.f1035l.m2123b(false);
    }

    public boolean expandActionView() {
        return !m2238n() ? false : (this.f1043t == null || this.f1043t.m887a(this)) ? this.f1035l.m2128c(this) : false;
    }

    boolean m2230f() {
        return this.f1035l.m2127c() && m2226d() != '\u0000';
    }

    public boolean m2231g() {
        return (this.f1039p & 4) != 0;
    }

    public ActionProvider getActionProvider() {
        throw new UnsupportedOperationException("This is not supported, use MenuItemCompat.getActionProvider()");
    }

    public View getActionView() {
        if (this.f1041r != null) {
            return this.f1041r;
        }
        if (this.f1042s == null) {
            return null;
        }
        this.f1041r = this.f1042s.m1335a((MenuItem) this);
        return this.f1041r;
    }

    public char getAlphabeticShortcut() {
        return this.f1032i;
    }

    public int getGroupId() {
        return this.f1025b;
    }

    public Drawable getIcon() {
        if (this.f1033j != null) {
            return this.f1033j;
        }
        if (this.f1034k == 0) {
            return null;
        }
        Drawable a = ao.m2497a().m2520a(this.f1035l.m2131e(), this.f1034k);
        this.f1034k = 0;
        this.f1033j = a;
        return a;
    }

    public Intent getIntent() {
        return this.f1030g;
    }

    @CapturedViewProperty
    public int getItemId() {
        return this.f1024a;
    }

    public ContextMenuInfo getMenuInfo() {
        return this.f1045v;
    }

    public char getNumericShortcut() {
        return this.f1031h;
    }

    public int getOrder() {
        return this.f1026c;
    }

    public SubMenu getSubMenu() {
        return this.f1036m;
    }

    @CapturedViewProperty
    public CharSequence getTitle() {
        return this.f1028e;
    }

    public CharSequence getTitleCondensed() {
        CharSequence charSequence = this.f1029f != null ? this.f1029f : this.f1028e;
        return (VERSION.SDK_INT >= 18 || charSequence == null || (charSequence instanceof String)) ? charSequence : charSequence.toString();
    }

    public void m2232h() {
        this.f1035l.m2121b(this);
    }

    public boolean hasSubMenu() {
        return this.f1036m != null;
    }

    public boolean m2233i() {
        return this.f1035l.m2143q();
    }

    public boolean isActionViewExpanded() {
        return this.f1044u;
    }

    public boolean isCheckable() {
        return (this.f1039p & 1) == 1;
    }

    public boolean isChecked() {
        return (this.f1039p & 2) == 2;
    }

    public boolean isEnabled() {
        return (this.f1039p & 16) != 0;
    }

    public boolean isVisible() {
        return (this.f1042s == null || !this.f1042s.m1340b()) ? (this.f1039p & 8) == 0 : (this.f1039p & 8) == 0 && this.f1042s.m1341c();
    }

    public boolean m2234j() {
        return (this.f1039p & 32) == 32;
    }

    public boolean m2235k() {
        return (this.f1040q & 1) == 1;
    }

    public boolean m2236l() {
        return (this.f1040q & 2) == 2;
    }

    public boolean m2237m() {
        return (this.f1040q & 4) == 4;
    }

    public boolean m2238n() {
        if ((this.f1040q & 8) == 0) {
            return false;
        }
        if (this.f1041r == null && this.f1042s != null) {
            this.f1041r = this.f1042s.m1335a((MenuItem) this);
        }
        return this.f1041r != null;
    }

    public MenuItem setActionProvider(ActionProvider actionProvider) {
        throw new UnsupportedOperationException("This is not supported, use MenuItemCompat.setActionProvider()");
    }

    public /* synthetic */ MenuItem setActionView(int i) {
        return m2212a(i);
    }

    public /* synthetic */ MenuItem setActionView(View view) {
        return m2215a(view);
    }

    public MenuItem setAlphabeticShortcut(char c) {
        if (this.f1032i != c) {
            this.f1032i = Character.toLowerCase(c);
            this.f1035l.m2123b(false);
        }
        return this;
    }

    public MenuItem setCheckable(boolean z) {
        int i = this.f1039p;
        this.f1039p = (z ? 1 : 0) | (this.f1039p & -2);
        if (i != this.f1039p) {
            this.f1035l.m2123b(false);
        }
        return this;
    }

    public MenuItem setChecked(boolean z) {
        if ((this.f1039p & 4) != 0) {
            this.f1035l.m2113a((MenuItem) this);
        } else {
            m2222b(z);
        }
        return this;
    }

    public MenuItem setEnabled(boolean z) {
        if (z) {
            this.f1039p |= 16;
        } else {
            this.f1039p &= -17;
        }
        this.f1035l.m2123b(false);
        return this;
    }

    public MenuItem setIcon(int i) {
        this.f1033j = null;
        this.f1034k = i;
        this.f1035l.m2123b(false);
        return this;
    }

    public MenuItem setIcon(Drawable drawable) {
        this.f1034k = 0;
        this.f1033j = drawable;
        this.f1035l.m2123b(false);
        return this;
    }

    public MenuItem setIntent(Intent intent) {
        this.f1030g = intent;
        return this;
    }

    public MenuItem setNumericShortcut(char c) {
        if (this.f1031h != c) {
            this.f1031h = c;
            this.f1035l.m2123b(false);
        }
        return this;
    }

    public MenuItem setOnActionExpandListener(OnActionExpandListener onActionExpandListener) {
        throw new UnsupportedOperationException("This is not supported, use MenuItemCompat.setOnActionExpandListener()");
    }

    public MenuItem setOnMenuItemClickListener(OnMenuItemClickListener onMenuItemClickListener) {
        this.f1038o = onMenuItemClickListener;
        return this;
    }

    public MenuItem setShortcut(char c, char c2) {
        this.f1031h = c;
        this.f1032i = Character.toLowerCase(c2);
        this.f1035l.m2123b(false);
        return this;
    }

    public void setShowAsAction(int i) {
        switch (i & 3) {
            case C0243l.View_android_theme /*0*/:
            case C0243l.View_android_focusable /*1*/:
            case C0243l.View_paddingStart /*2*/:
                this.f1040q = i;
                this.f1035l.m2121b(this);
            default:
                throw new IllegalArgumentException("SHOW_AS_ACTION_ALWAYS, SHOW_AS_ACTION_IF_ROOM, and SHOW_AS_ACTION_NEVER are mutually exclusive.");
        }
    }

    public /* synthetic */ MenuItem setShowAsActionFlags(int i) {
        return m2221b(i);
    }

    public MenuItem setTitle(int i) {
        return setTitle(this.f1035l.m2131e().getString(i));
    }

    public MenuItem setTitle(CharSequence charSequence) {
        this.f1028e = charSequence;
        this.f1035l.m2123b(false);
        if (this.f1036m != null) {
            this.f1036m.setHeaderTitle(charSequence);
        }
        return this;
    }

    public MenuItem setTitleCondensed(CharSequence charSequence) {
        this.f1029f = charSequence;
        if (charSequence == null) {
            CharSequence charSequence2 = this.f1028e;
        }
        this.f1035l.m2123b(false);
        return this;
    }

    public MenuItem setVisible(boolean z) {
        if (m2225c(z)) {
            this.f1035l.m2110a(this);
        }
        return this;
    }

    public String toString() {
        return this.f1028e != null ? this.f1028e.toString() : null;
    }
}
