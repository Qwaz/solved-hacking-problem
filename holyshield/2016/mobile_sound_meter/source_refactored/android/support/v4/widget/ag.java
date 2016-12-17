package android.support.v4.widget;

import android.os.Parcel;
import android.os.Parcelable.Creator;

final class ag implements Creator {
    ag() {
    }

    public af m1430a(Parcel parcel) {
        return new af(parcel);
    }

    public af[] m1431a(int i) {
        return new af[i];
    }

    public /* synthetic */ Object createFromParcel(Parcel parcel) {
        return m1430a(parcel);
    }

    public /* synthetic */ Object[] newArray(int i) {
        return m1431a(i);
    }
}
