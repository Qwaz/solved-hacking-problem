package android.support.v7.view.menu;

import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import java.util.ArrayList;

/* renamed from: android.support.v7.view.menu.h */
class C0270h extends BaseAdapter {
    final /* synthetic */ C0269g f1014a;
    private int f1015b;

    public C0270h(C0269g c0269g) {
        this.f1014a = c0269g;
        this.f1015b = -1;
        m2206a();
    }

    public C0272m m2205a(int i) {
        ArrayList l = this.f1014a.f1007c.m2138l();
        int a = this.f1014a.f1012h + i;
        if (this.f1015b >= 0 && a >= this.f1015b) {
            a++;
        }
        return (C0272m) l.get(a);
    }

    void m2206a() {
        C0272m r = this.f1014a.f1007c.m2144r();
        if (r != null) {
            ArrayList l = this.f1014a.f1007c.m2138l();
            int size = l.size();
            for (int i = 0; i < size; i++) {
                if (((C0272m) l.get(i)) == r) {
                    this.f1015b = i;
                    return;
                }
            }
        }
        this.f1015b = -1;
    }

    public int getCount() {
        int size = this.f1014a.f1007c.m2138l().size() - this.f1014a.f1012h;
        return this.f1015b < 0 ? size : size - 1;
    }

    public /* synthetic */ Object getItem(int i) {
        return m2205a(i);
    }

    public long getItemId(int i) {
        return (long) i;
    }

    public View getView(int i, View view, ViewGroup viewGroup) {
        View inflate = view == null ? this.f1014a.f1006b.inflate(this.f1014a.f1010f, viewGroup, false) : view;
        ((aa) inflate).m2055a(m2205a(i), 0);
        return inflate;
    }

    public void notifyDataSetChanged() {
        m2206a();
        super.notifyDataSetChanged();
    }
}
