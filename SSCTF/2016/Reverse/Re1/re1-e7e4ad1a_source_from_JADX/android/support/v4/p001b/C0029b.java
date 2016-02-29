package android.support.v4.p001b;

import android.os.Parcel;
import android.os.Parcelable.Creator;

/* renamed from: android.support.v4.b.b */
class C0029b implements Creator {
    final C0030c f187a;

    public C0029b(C0030c c0030c) {
        this.f187a = c0030c;
    }

    public Object createFromParcel(Parcel parcel) {
        return this.f187a.m199a(parcel, null);
    }

    public Object[] newArray(int i) {
        return this.f187a.m200a(i);
    }
}
