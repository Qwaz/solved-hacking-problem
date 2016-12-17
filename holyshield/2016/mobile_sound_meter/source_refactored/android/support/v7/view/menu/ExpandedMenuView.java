package android.support.v7.view.menu;

import android.content.Context;
import android.support.v7.widget.dh;
import android.util.AttributeSet;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;

public final class ExpandedMenuView extends ListView implements C0259k, C0260z, OnItemClickListener {
    private static final int[] f922a;
    private C0264i f923b;
    private int f924c;

    static {
        f922a = new int[]{16842964, 16843049};
    }

    public ExpandedMenuView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 16842868);
    }

    public ExpandedMenuView(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet);
        setOnItemClickListener(this);
        dh a = dh.m2710a(context, attributeSet, f922a, i, 0);
        if (a.m2725f(0)) {
            setBackgroundDrawable(a.m2713a(0));
        }
        if (a.m2725f(1)) {
            setDivider(a.m2713a(1));
        }
        a.m2714a();
    }

    public void m2070a(C0264i c0264i) {
        this.f923b = c0264i;
    }

    public boolean m2071a(C0272m c0272m) {
        return this.f923b.m2117a((MenuItem) c0272m, 0);
    }

    public int getWindowAnimations() {
        return this.f924c;
    }

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        setChildrenDrawingCacheEnabled(false);
    }

    public void onItemClick(AdapterView adapterView, View view, int i, long j) {
        m2071a((C0272m) getAdapter().getItem(i));
    }
}
