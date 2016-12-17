package android.support.v7.view.menu;

import android.content.Context;
import android.support.v4.p008d.p009a.C0090b;
import android.support.v4.p008d.p009a.C0091c;
import android.support.v4.p012g.C0107a;
import android.view.MenuItem;
import android.view.SubMenu;
import java.util.Iterator;
import java.util.Map;

/* renamed from: android.support.v7.view.menu.e */
abstract class C0263e extends C0262f {
    final Context f954a;
    private Map f955c;
    private Map f956d;

    C0263e(Context context, Object obj) {
        super(obj);
        this.f954a = context;
    }

    final MenuItem m2087a(MenuItem menuItem) {
        if (!(menuItem instanceof C0090b)) {
            return menuItem;
        }
        C0090b c0090b = (C0090b) menuItem;
        if (this.f955c == null) {
            this.f955c = new C0107a();
        }
        MenuItem menuItem2 = (MenuItem) this.f955c.get(menuItem);
        if (menuItem2 != null) {
            return menuItem2;
        }
        menuItem2 = ab.m2085a(this.f954a, c0090b);
        this.f955c.put(c0090b, menuItem2);
        return menuItem2;
    }

    final SubMenu m2088a(SubMenu subMenu) {
        if (!(subMenu instanceof C0091c)) {
            return subMenu;
        }
        C0091c c0091c = (C0091c) subMenu;
        if (this.f956d == null) {
            this.f956d = new C0107a();
        }
        SubMenu subMenu2 = (SubMenu) this.f956d.get(c0091c);
        if (subMenu2 != null) {
            return subMenu2;
        }
        subMenu2 = ab.m2086a(this.f954a, c0091c);
        this.f956d.put(c0091c, subMenu2);
        return subMenu2;
    }

    final void m2089a() {
        if (this.f955c != null) {
            this.f955c.clear();
        }
        if (this.f956d != null) {
            this.f956d.clear();
        }
    }

    final void m2090a(int i) {
        if (this.f955c != null) {
            Iterator it = this.f955c.keySet().iterator();
            while (it.hasNext()) {
                if (i == ((MenuItem) it.next()).getGroupId()) {
                    it.remove();
                }
            }
        }
    }

    final void m2091b(int i) {
        if (this.f955c != null) {
            Iterator it = this.f955c.keySet().iterator();
            while (it.hasNext()) {
                if (i == ((MenuItem) it.next()).getItemId()) {
                    it.remove();
                    return;
                }
            }
        }
    }
}
