package android.support.v7.widget;

import android.support.v7.view.menu.C0261a;
import android.view.View;
import android.view.View.OnClickListener;

class dr implements OnClickListener {
    final C0261a f1550a;
    final /* synthetic */ dq f1551b;

    dr(dq dqVar) {
        this.f1551b = dqVar;
        this.f1550a = new C0261a(this.f1551b.f1532a.getContext(), 0, 16908332, 0, 0, this.f1551b.f1540i);
    }

    public void onClick(View view) {
        if (this.f1551b.f1543l != null && this.f1551b.f1544m) {
            this.f1551b.f1543l.onMenuItemSelected(0, this.f1550a);
        }
    }
}
