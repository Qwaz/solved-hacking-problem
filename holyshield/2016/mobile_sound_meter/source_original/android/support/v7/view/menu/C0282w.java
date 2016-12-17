package android.support.v7.view.menu;

import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import java.util.ArrayList;

/* renamed from: android.support.v7.view.menu.w */
class C0282w extends BaseAdapter {
    final /* synthetic */ C0281v f1073a;
    private C0264i f1074b;
    private int f1075c;

    public C0282w(C0281v c0281v, C0264i c0264i) {
        this.f1073a = c0281v;
        this.f1075c = -1;
        this.f1074b = c0264i;
        m2278a();
    }

    public C0272m m2277a(int i) {
        ArrayList l = this.f1073a.f1061g ? this.f1074b.m2138l() : this.f1074b.m2135i();
        if (this.f1075c >= 0 && i >= this.f1075c) {
            i++;
        }
        return (C0272m) l.get(i);
    }

    void m2278a() {
        C0272m r = this.f1073a.f1059e.m2144r();
        if (r != null) {
            ArrayList l = this.f1073a.f1059e.m2138l();
            int size = l.size();
            for (int i = 0; i < size; i++) {
                if (((C0272m) l.get(i)) == r) {
                    this.f1075c = i;
                    return;
                }
            }
        }
        this.f1075c = -1;
    }

    public int getCount() {
        ArrayList l = this.f1073a.f1061g ? this.f1074b.m2138l() : this.f1074b.m2135i();
        return this.f1075c < 0 ? l.size() : l.size() - 1;
    }

    public /* synthetic */ Object getItem(int i) {
        return m2277a(i);
    }

    public long getItemId(int i) {
        return (long) i;
    }

    public View getView(int i, View view, ViewGroup viewGroup) {
        View inflate = view == null ? this.f1073a.f1058d.inflate(C0281v.f1055a, viewGroup, false) : view;
        aa aaVar = (aa) inflate;
        if (this.f1073a.f1056b) {
            ((ListMenuItemView) inflate).setForceShowIcon(true);
        }
        aaVar.m2055a(m2277a(i), 0);
        return inflate;
    }

    public void notifyDataSetChanged() {
        m2278a();
        super.notifyDataSetChanged();
    }
}
