package android.support.v4.widget;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import android.support.v4.widget.DrawerLayout.SavedState;

/* renamed from: android.support.v4.widget.c */
final class C0064c implements Creator {
    C0064c() {
    }

    public SavedState m447a(Parcel parcel) {
        return new SavedState(parcel);
    }

    public SavedState[] m448a(int i) {
        return new SavedState[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m447a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m448a(i);
    }
}
