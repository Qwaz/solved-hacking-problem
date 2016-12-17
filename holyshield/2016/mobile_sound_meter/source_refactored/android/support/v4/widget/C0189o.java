package android.support.v4.widget;

import android.database.ContentObserver;
import android.os.Handler;

/* renamed from: android.support.v4.widget.o */
class C0189o extends ContentObserver {
    final /* synthetic */ C0176m f560a;

    public C0189o(C0176m c0176m) {
        this.f560a = c0176m;
        super(new Handler());
    }

    public boolean deliverSelfNotifications() {
        return true;
    }

    public void onChange(boolean z) {
        this.f560a.m1463b();
    }
}
