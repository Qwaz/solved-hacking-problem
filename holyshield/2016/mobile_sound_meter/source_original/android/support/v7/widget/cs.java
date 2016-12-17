package android.support.v7.widget;

import android.view.View;
import android.view.View.OnClickListener;

class cs implements OnClickListener {
    final /* synthetic */ cp f1472a;

    private cs(cp cpVar) {
        this.f1472a = cpVar;
    }

    public void onClick(View view) {
        ((ct) view).m2669b().m1915d();
        int childCount = this.f1472a.f1464e.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = this.f1472a.f1464e.getChildAt(i);
            childAt.setSelected(childAt == view);
        }
    }
}
