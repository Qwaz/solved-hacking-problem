package android.support.v7.widget;

import android.os.Parcel;
import android.os.Parcelable.Creator;

final class dp implements Creator {
    dp() {
    }

    public C0288do m2738a(Parcel parcel) {
        return new C0288do(parcel);
    }

    public C0288do[] m2739a(int i) {
        return new C0288do[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m2738a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m2739a(i);
    }
}
