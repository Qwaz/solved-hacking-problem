package android.support.v4.widget;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.view.View.BaseSavedState;

class af extends BaseSavedState {
    public static final Creator CREATOR;
    public int f526a;

    static {
        CREATOR = new ag();
    }

    public af(Parcel parcel) {
        super(parcel);
        this.f526a = parcel.readInt();
    }

    af(Parcelable parcelable) {
        super(parcelable);
    }

    public String toString() {
        return "HorizontalScrollView.SavedState{" + Integer.toHexString(System.identityHashCode(this)) + " scrollPosition=" + this.f526a + "}";
    }

    public void writeToParcel(Parcel parcel, int i) {
        super.writeToParcel(parcel, i);
        parcel.writeInt(this.f526a);
    }
}
