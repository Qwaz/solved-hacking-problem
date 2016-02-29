package android.support.v4.app;

import android.view.View;

/* renamed from: android.support.v4.app.e */
class C0008e implements C0007k {
    final /* synthetic */ Fragment f109a;

    C0008e(Fragment fragment) {
        this.f109a = fragment;
    }

    public View m88a(int i) {
        if (this.f109a.f26I != null) {
            return this.f109a.f26I.findViewById(i);
        }
        throw new IllegalStateException("Fragment does not have a view");
    }
}
