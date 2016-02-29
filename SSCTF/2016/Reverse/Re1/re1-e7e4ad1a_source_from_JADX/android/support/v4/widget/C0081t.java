package android.support.v4.widget;

import android.os.Parcel;
import android.os.Parcelable.Creator;

/* renamed from: android.support.v4.widget.t */
final class C0081t implements Creator {
    C0081t() {
    }

    public SavedState m532a(Parcel parcel) {
        return new SavedState(null);
    }

    public SavedState[] m533a(int i) {
        return new SavedState[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m532a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m533a(i);
    }
}
