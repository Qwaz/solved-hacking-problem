package android.support.v7.widget;

import android.database.DataSetObserver;

class ch extends DataSetObserver {
    final /* synthetic */ by f1445a;

    private ch(by byVar) {
        this.f1445a = byVar;
    }

    public void onChanged() {
        if (this.f1445a.m2581k()) {
            this.f1445a.m2567c();
        }
    }

    public void onInvalidated() {
        this.f1445a.m2579i();
    }
}
