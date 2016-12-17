package android.support.v4.widget;

import android.database.DataSetObserver;

/* renamed from: android.support.v4.widget.p */
class C0190p extends DataSetObserver {
    final /* synthetic */ C0176m f561a;

    private C0190p(C0176m c0176m) {
        this.f561a = c0176m;
    }

    public void onChanged() {
        this.f561a.f531a = true;
        this.f561a.notifyDataSetChanged();
    }

    public void onInvalidated() {
        this.f561a.f531a = false;
        this.f561a.notifyDataSetInvalidated();
    }
}
