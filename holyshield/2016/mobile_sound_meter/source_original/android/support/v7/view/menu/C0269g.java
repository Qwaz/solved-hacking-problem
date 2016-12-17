package android.support.v7.view.menu;

import android.content.Context;
import android.support.v7.p015b.C0240i;
import android.view.ContextThemeWrapper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListAdapter;

/* renamed from: android.support.v7.view.menu.g */
public class C0269g implements C0267x, OnItemClickListener {
    Context f1005a;
    LayoutInflater f1006b;
    C0264i f1007c;
    ExpandedMenuView f1008d;
    int f1009e;
    int f1010f;
    C0270h f1011g;
    private int f1012h;
    private C0207y f1013i;

    public C0269g(int i, int i2) {
        this.f1010f = i;
        this.f1009e = i2;
    }

    public C0269g(Context context, int i) {
        this(i, 0);
        this.f1005a = context;
        this.f1006b = LayoutInflater.from(this.f1005a);
    }

    public C0260z m2195a(ViewGroup viewGroup) {
        if (this.f1008d == null) {
            this.f1008d = (ExpandedMenuView) this.f1006b.inflate(C0240i.abc_expanded_menu_layout, viewGroup, false);
            if (this.f1011g == null) {
                this.f1011g = new C0270h(this);
            }
            this.f1008d.setAdapter(this.f1011g);
            this.f1008d.setOnItemClickListener(this);
        }
        return this.f1008d;
    }

    public ListAdapter m2196a() {
        if (this.f1011g == null) {
            this.f1011g = new C0270h(this);
        }
        return this.f1011g;
    }

    public void m2197a(Context context, C0264i c0264i) {
        if (this.f1009e != 0) {
            this.f1005a = new ContextThemeWrapper(context, this.f1009e);
            this.f1006b = LayoutInflater.from(this.f1005a);
        } else if (this.f1005a != null) {
            this.f1005a = context;
            if (this.f1006b == null) {
                this.f1006b = LayoutInflater.from(this.f1005a);
            }
        }
        this.f1007c = c0264i;
        if (this.f1011g != null) {
            this.f1011g.notifyDataSetChanged();
        }
    }

    public void m2198a(C0264i c0264i, boolean z) {
        if (this.f1013i != null) {
            this.f1013i.m1754a(c0264i, z);
        }
    }

    public void m2199a(C0207y c0207y) {
        this.f1013i = c0207y;
    }

    public boolean m2200a(ad adVar) {
        if (!adVar.hasVisibleItems()) {
            return false;
        }
        new C0271l(adVar).m2208a(null);
        if (this.f1013i != null) {
            this.f1013i.m1755a(adVar);
        }
        return true;
    }

    public boolean m2201a(C0264i c0264i, C0272m c0272m) {
        return false;
    }

    public void m2202b(boolean z) {
        if (this.f1011g != null) {
            this.f1011g.notifyDataSetChanged();
        }
    }

    public boolean m2203b() {
        return false;
    }

    public boolean m2204b(C0264i c0264i, C0272m c0272m) {
        return false;
    }

    public void onItemClick(AdapterView adapterView, View view, int i, long j) {
        this.f1007c.m2118a(this.f1011g.m2205a(i), (C0267x) this, 0);
    }
}
