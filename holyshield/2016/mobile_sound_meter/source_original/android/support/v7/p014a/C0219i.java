package android.support.v7.p014a;

import android.view.View;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;

/* renamed from: android.support.v7.a.i */
class C0219i implements OnScrollListener {
    final /* synthetic */ View f781a;
    final /* synthetic */ View f782b;
    final /* synthetic */ C0215e f783c;

    C0219i(C0215e c0215e, View view, View view2) {
        this.f783c = c0215e;
        this.f781a = view;
        this.f782b = view2;
    }

    public void onScroll(AbsListView absListView, int i, int i2, int i3) {
        C0215e.m1928b(absListView, this.f781a, this.f782b);
    }

    public void onScrollStateChanged(AbsListView absListView, int i) {
    }
}
