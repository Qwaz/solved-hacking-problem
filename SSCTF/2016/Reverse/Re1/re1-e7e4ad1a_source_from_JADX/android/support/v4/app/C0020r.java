package android.support.v4.app;

import android.os.Parcel;
import android.os.Parcelable.Creator;

/* renamed from: android.support.v4.app.r */
final class C0020r implements Creator {
    C0020r() {
    }

    public FragmentState m167a(Parcel parcel) {
        return new FragmentState(parcel);
    }

    public FragmentState[] m168a(int i) {
        return new FragmentState[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m167a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m168a(i);
    }
}
