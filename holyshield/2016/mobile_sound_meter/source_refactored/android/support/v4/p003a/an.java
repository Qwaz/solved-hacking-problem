package android.support.v4.p003a;

import android.os.Parcel;
import android.os.Parcelable.Creator;

/* renamed from: android.support.v4.a.an */
final class an implements Creator {
    an() {
    }

    public am m203a(Parcel parcel) {
        return new am(parcel);
    }

    public am[] m204a(int i) {
        return new am[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m203a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m204a(i);
    }
}
