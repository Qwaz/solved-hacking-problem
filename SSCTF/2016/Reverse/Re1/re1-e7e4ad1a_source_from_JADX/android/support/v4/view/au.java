package android.support.v4.view;

import android.database.DataSetObserver;

class au extends DataSetObserver {
    final /* synthetic */ ViewPager f261a;

    private au(ViewPager viewPager) {
        this.f261a = viewPager;
    }

    public void onChanged() {
        this.f261a.m230a();
    }

    public void onInvalidated() {
        this.f261a.m230a();
    }
}
