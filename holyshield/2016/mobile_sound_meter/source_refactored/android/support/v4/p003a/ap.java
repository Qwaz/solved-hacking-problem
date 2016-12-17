package android.support.v4.p003a;

import android.os.Parcel;
import android.os.Parcelable.Creator;

/* renamed from: android.support.v4.a.ap */
final class ap implements Creator {
    ap() {
    }

    public ao m206a(Parcel parcel) {
        return new ao(parcel);
    }

    public ao[] m207a(int i) {
        return new ao[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m206a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m207a(i);
    }
}
