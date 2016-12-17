package android.support.v7.view;

import android.content.Context;
import android.support.v4.p008d.p009a.C0089a;
import android.support.v4.p008d.p009a.C0090b;
import android.support.v4.p012g.C0106n;
import android.support.v7.view.menu.ab;
import android.view.ActionMode;
import android.view.ActionMode.Callback;
import android.view.Menu;
import android.view.MenuItem;
import java.util.ArrayList;

/* renamed from: android.support.v7.view.h */
public class C0252h implements C0208c {
    final Callback f860a;
    final Context f861b;
    final ArrayList f862c;
    final C0106n f863d;

    public C0252h(Context context, Callback callback) {
        this.f861b = context;
        this.f860a = callback;
        this.f862c = new ArrayList();
        this.f863d = new C0106n();
    }

    private Menu m2016a(Menu menu) {
        Menu menu2 = (Menu) this.f863d.get(menu);
        if (menu2 != null) {
            return menu2;
        }
        menu2 = ab.m2084a(this.f861b, (C0089a) menu);
        this.f863d.put(menu, menu2);
        return menu2;
    }

    public void m2017a(C0212b c0212b) {
        this.f860a.onDestroyActionMode(m2020b(c0212b));
    }

    public boolean m2018a(C0212b c0212b, Menu menu) {
        return this.f860a.onCreateActionMode(m2020b(c0212b), m2016a(menu));
    }

    public boolean m2019a(C0212b c0212b, MenuItem menuItem) {
        return this.f860a.onActionItemClicked(m2020b(c0212b), ab.m2085a(this.f861b, (C0090b) menuItem));
    }

    public ActionMode m2020b(C0212b c0212b) {
        int size = this.f862c.size();
        for (int i = 0; i < size; i++) {
            C0251g c0251g = (C0251g) this.f862c.get(i);
            if (c0251g != null && c0251g.f859b == c0212b) {
                return c0251g;
            }
        }
        ActionMode c0251g2 = new C0251g(this.f861b, c0212b);
        this.f862c.add(c0251g2);
        return c0251g2;
    }

    public boolean m2021b(C0212b c0212b, Menu menu) {
        return this.f860a.onPrepareActionMode(m2020b(c0212b), m2016a(menu));
    }
}
