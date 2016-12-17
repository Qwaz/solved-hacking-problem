package android.support.v4.p003a;

import android.os.Parcel;
import android.os.Parcelable.Creator;

/* renamed from: android.support.v4.a.q */
final class C0039q implements Creator {
    C0039q() {
    }

    public C0038p m336a(Parcel parcel) {
        return new C0038p(parcel);
    }

    public C0038p[] m337a(int i) {
        return new C0038p[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m336a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m337a(i);
    }
}
