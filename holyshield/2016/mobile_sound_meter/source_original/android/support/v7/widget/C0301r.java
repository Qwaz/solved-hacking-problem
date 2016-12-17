package android.support.v7.widget;

import android.content.Context;
import android.support.v7.p015b.C0233b;
import android.support.v7.view.menu.C0264i;
import android.support.v7.view.menu.C0281v;
import android.view.View;

/* renamed from: android.support.v7.widget.r */
class C0301r extends C0281v {
    final /* synthetic */ C0294k f1591c;

    public C0301r(C0294k c0294k, Context context, C0264i c0264i, View view, boolean z) {
        this.f1591c = c0294k;
        super(context, c0264i, view, z, C0233b.actionOverflowMenuStyle);
        m2261a(8388613);
        m2264a(c0294k.f1562g);
    }

    public void onDismiss() {
        super.onDismiss();
        if (this.f1591c.c != null) {
            this.f1591c.c.close();
        }
        this.f1591c.f1579x = null;
    }
}
