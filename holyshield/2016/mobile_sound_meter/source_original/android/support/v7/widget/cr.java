package android.support.v7.widget;

import android.support.v7.p014a.C0214d;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;

class cr extends BaseAdapter {
    final /* synthetic */ cp f1471a;

    private cr(cp cpVar) {
        this.f1471a = cpVar;
    }

    public int getCount() {
        return this.f1471a.f1464e.getChildCount();
    }

    public Object getItem(int i) {
        return ((ct) this.f1471a.f1464e.getChildAt(i)).m2669b();
    }

    public long getItemId(int i) {
        return (long) i;
    }

    public View getView(int i, View view, ViewGroup viewGroup) {
        if (view == null) {
            return this.f1471a.m2660a((C0214d) getItem(i), true);
        }
        ((ct) view).m2668a((C0214d) getItem(i));
        return view;
    }
}
