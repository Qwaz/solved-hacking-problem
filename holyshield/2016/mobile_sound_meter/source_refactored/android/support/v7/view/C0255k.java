package android.support.v7.view;

import android.content.res.TypedArray;
import android.support.v4.p004h.C0161n;
import android.support.v4.p004h.ar;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.menu.C0272m;
import android.support.v7.view.menu.C0274o;
import android.util.AttributeSet;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;
import java.lang.reflect.Constructor;

/* renamed from: android.support.v7.view.k */
class C0255k {
    final /* synthetic */ C0253i f873a;
    private Menu f874b;
    private int f875c;
    private int f876d;
    private int f877e;
    private int f878f;
    private boolean f879g;
    private boolean f880h;
    private boolean f881i;
    private int f882j;
    private int f883k;
    private CharSequence f884l;
    private CharSequence f885m;
    private int f886n;
    private char f887o;
    private char f888p;
    private int f889q;
    private boolean f890r;
    private boolean f891s;
    private boolean f892t;
    private int f893u;
    private int f894v;
    private String f895w;
    private String f896x;
    private String f897y;
    private C0161n f898z;

    public C0255k(C0253i c0253i, Menu menu) {
        this.f873a = c0253i;
        this.f874b = menu;
        m2035a();
    }

    private char m2031a(String str) {
        return str == null ? '\u0000' : str.charAt(0);
    }

    private Object m2033a(String str, Class[] clsArr, Object[] objArr) {
        try {
            Constructor constructor = this.f873a.f868e.getClassLoader().loadClass(str).getConstructor(clsArr);
            constructor.setAccessible(true);
            return constructor.newInstance(objArr);
        } catch (Throwable e) {
            Log.w("SupportMenuInflater", "Cannot instantiate class: " + str, e);
            return null;
        }
    }

    private void m2034a(MenuItem menuItem) {
        boolean z = true;
        menuItem.setChecked(this.f890r).setVisible(this.f891s).setEnabled(this.f892t).setCheckable(this.f889q >= 1).setTitleCondensed(this.f885m).setIcon(this.f886n).setAlphabeticShortcut(this.f887o).setNumericShortcut(this.f888p);
        if (this.f893u >= 0) {
            ar.m863a(menuItem, this.f893u);
        }
        if (this.f897y != null) {
            if (this.f873a.f868e.isRestricted()) {
                throw new IllegalStateException("The android:onClick attribute cannot be used within a restricted context");
            }
            menuItem.setOnMenuItemClickListener(new C0254j(this.f873a.m2028c(), this.f897y));
        }
        if (menuItem instanceof C0272m) {
            C0272m c0272m = (C0272m) menuItem;
        }
        if (this.f889q >= 2) {
            if (menuItem instanceof C0272m) {
                ((C0272m) menuItem).m2220a(true);
            } else if (menuItem instanceof C0274o) {
                ((C0274o) menuItem).m2241a(true);
            }
        }
        if (this.f895w != null) {
            ar.m861a(menuItem, (View) m2033a(this.f895w, C0253i.f864a, this.f873a.f866c));
        } else {
            z = false;
        }
        if (this.f894v > 0) {
            if (z) {
                Log.w("SupportMenuInflater", "Ignoring attribute 'itemActionViewLayout'. Action view already specified.");
            } else {
                ar.m864b(menuItem, this.f894v);
            }
        }
        if (this.f898z != null) {
            ar.m860a(menuItem, this.f898z);
        }
    }

    public void m2035a() {
        this.f875c = 0;
        this.f876d = 0;
        this.f877e = 0;
        this.f878f = 0;
        this.f879g = true;
        this.f880h = true;
    }

    public void m2036a(AttributeSet attributeSet) {
        TypedArray obtainStyledAttributes = this.f873a.f868e.obtainStyledAttributes(attributeSet, C0243l.MenuGroup);
        this.f875c = obtainStyledAttributes.getResourceId(C0243l.MenuGroup_android_id, 0);
        this.f876d = obtainStyledAttributes.getInt(C0243l.MenuGroup_android_menuCategory, 0);
        this.f877e = obtainStyledAttributes.getInt(C0243l.MenuGroup_android_orderInCategory, 0);
        this.f878f = obtainStyledAttributes.getInt(C0243l.MenuGroup_android_checkableBehavior, 0);
        this.f879g = obtainStyledAttributes.getBoolean(C0243l.MenuGroup_android_visible, true);
        this.f880h = obtainStyledAttributes.getBoolean(C0243l.MenuGroup_android_enabled, true);
        obtainStyledAttributes.recycle();
    }

    public void m2037b() {
        this.f881i = true;
        m2034a(this.f874b.add(this.f875c, this.f882j, this.f883k, this.f884l));
    }

    public void m2038b(AttributeSet attributeSet) {
        boolean z = true;
        TypedArray obtainStyledAttributes = this.f873a.f868e.obtainStyledAttributes(attributeSet, C0243l.MenuItem);
        this.f882j = obtainStyledAttributes.getResourceId(C0243l.MenuItem_android_id, 0);
        this.f883k = (obtainStyledAttributes.getInt(C0243l.MenuItem_android_menuCategory, this.f876d) & -65536) | (obtainStyledAttributes.getInt(C0243l.MenuItem_android_orderInCategory, this.f877e) & 65535);
        this.f884l = obtainStyledAttributes.getText(C0243l.MenuItem_android_title);
        this.f885m = obtainStyledAttributes.getText(C0243l.MenuItem_android_titleCondensed);
        this.f886n = obtainStyledAttributes.getResourceId(C0243l.MenuItem_android_icon, 0);
        this.f887o = m2031a(obtainStyledAttributes.getString(C0243l.MenuItem_android_alphabeticShortcut));
        this.f888p = m2031a(obtainStyledAttributes.getString(C0243l.MenuItem_android_numericShortcut));
        if (obtainStyledAttributes.hasValue(C0243l.MenuItem_android_checkable)) {
            this.f889q = obtainStyledAttributes.getBoolean(C0243l.MenuItem_android_checkable, false) ? 1 : 0;
        } else {
            this.f889q = this.f878f;
        }
        this.f890r = obtainStyledAttributes.getBoolean(C0243l.MenuItem_android_checked, false);
        this.f891s = obtainStyledAttributes.getBoolean(C0243l.MenuItem_android_visible, this.f879g);
        this.f892t = obtainStyledAttributes.getBoolean(C0243l.MenuItem_android_enabled, this.f880h);
        this.f893u = obtainStyledAttributes.getInt(C0243l.MenuItem_showAsAction, -1);
        this.f897y = obtainStyledAttributes.getString(C0243l.MenuItem_android_onClick);
        this.f894v = obtainStyledAttributes.getResourceId(C0243l.MenuItem_actionLayout, 0);
        this.f895w = obtainStyledAttributes.getString(C0243l.MenuItem_actionViewClass);
        this.f896x = obtainStyledAttributes.getString(C0243l.MenuItem_actionProviderClass);
        if (this.f896x == null) {
            z = false;
        }
        if (z && this.f894v == 0 && this.f895w == null) {
            this.f898z = (C0161n) m2033a(this.f896x, C0253i.f865b, this.f873a.f867d);
        } else {
            if (z) {
                Log.w("SupportMenuInflater", "Ignoring attribute 'actionProviderClass'. Action view already specified.");
            }
            this.f898z = null;
        }
        obtainStyledAttributes.recycle();
        this.f881i = false;
    }

    public SubMenu m2039c() {
        this.f881i = true;
        SubMenu addSubMenu = this.f874b.addSubMenu(this.f875c, this.f882j, this.f883k, this.f884l);
        m2034a(addSubMenu.getItem());
        return addSubMenu;
    }

    public boolean m2040d() {
        return this.f881i;
    }
}
