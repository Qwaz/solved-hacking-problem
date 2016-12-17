package android.support.v7.view.menu;

import android.support.v7.view.C0248d;
import android.view.CollapsibleActionView;
import android.view.View;
import android.widget.FrameLayout;

/* renamed from: android.support.v7.view.menu.q */
class C0276q extends FrameLayout implements C0248d {
    final CollapsibleActionView f1050a;

    C0276q(View view) {
        super(view.getContext());
        this.f1050a = (CollapsibleActionView) view;
        addView(view);
    }

    public void m2246a() {
        this.f1050a.onActionViewExpanded();
    }

    public void m2247b() {
        this.f1050a.onActionViewCollapsed();
    }

    View m2248c() {
        return (View) this.f1050a;
    }
}
