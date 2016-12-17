package android.support.v7.widget;

import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;

class ci implements OnScrollListener {
    final /* synthetic */ by f1446a;

    private ci(by byVar) {
        this.f1446a = byVar;
    }

    public void onScroll(AbsListView absListView, int i, int i2, int i3) {
    }

    public void onScrollStateChanged(AbsListView absListView, int i) {
        if (i == 1 && !this.f1446a.m2582l() && this.f1446a.f1379e.getContentView() != null) {
            this.f1446a.f1373C.removeCallbacks(this.f1446a.f1398x);
            this.f1446a.f1398x.run();
        }
    }
}
