package android.support.v4.app;

import android.os.Parcel;
import android.os.Parcelable.Creator;

/* renamed from: android.support.v4.app.q */
final class C0019q implements Creator {
    C0019q() {
    }

    public FragmentManagerState m165a(Parcel parcel) {
        return new FragmentManagerState(parcel);
    }

    public FragmentManagerState[] m166a(int i) {
        return new FragmentManagerState[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m165a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m166a(i);
    }
}
