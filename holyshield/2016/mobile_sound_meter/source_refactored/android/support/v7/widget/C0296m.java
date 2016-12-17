package android.support.v7.widget;

import android.content.Context;
import android.support.v7.p015b.C0233b;
import android.support.v7.view.menu.C0272m;
import android.support.v7.view.menu.C0281v;
import android.support.v7.view.menu.ad;
import android.view.MenuItem;
import android.view.View;

/* renamed from: android.support.v7.widget.m */
class C0296m extends C0281v {
    final /* synthetic */ C0294k f1582c;
    private ad f1583d;

    public C0296m(C0294k c0294k, Context context, ad adVar) {
        boolean z = false;
        this.f1582c = c0294k;
        super(context, adVar, null, false, C0233b.actionOverflowMenuStyle);
        this.f1583d = adVar;
        if (!((C0272m) adVar.getItem()).m2234j()) {
            m2265a(c0294k.f1564i == null ? (View) c0294k.f : c0294k.f1564i);
        }
        m2264a(c0294k.f1562g);
        int size = adVar.size();
        for (int i = 0; i < size; i++) {
            MenuItem item = adVar.getItem(i);
            if (item.isVisible() && item.getIcon() != null) {
                z = true;
                break;
            }
        }
        m2266a(z);
    }

    public void onDismiss() {
        super.onDismiss();
        this.f1582c.f1580y = null;
        this.f1582c.f1563h = 0;
    }
}
