package android.support.v4.app;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import android.support.v4.app.Fragment.SavedState;

/* renamed from: android.support.v4.app.g */
final class C0010g implements Creator {
    C0010g() {
    }

    public SavedState m89a(Parcel parcel) {
        return new SavedState(parcel, null);
    }

    public SavedState[] m90a(int i) {
        return new SavedState[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m89a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m90a(i);
    }
}
