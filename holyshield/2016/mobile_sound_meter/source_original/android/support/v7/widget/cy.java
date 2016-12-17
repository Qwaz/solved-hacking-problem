package android.support.v7.widget;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.view.View.BaseSavedState;

class cy extends BaseSavedState {
    public static final Creator CREATOR;
    boolean f1483a;

    static {
        CREATOR = new cz();
    }

    public cy(Parcel parcel) {
        super(parcel);
        this.f1483a = ((Boolean) parcel.readValue(null)).booleanValue();
    }

    cy(Parcelable parcelable) {
        super(parcelable);
    }

    public String toString() {
        return "SearchView.SavedState{" + Integer.toHexString(System.identityHashCode(this)) + " isIconified=" + this.f1483a + "}";
    }

    public void writeToParcel(Parcel parcel, int i) {
        super.writeToParcel(parcel, i);
        parcel.writeValue(Boolean.valueOf(this.f1483a));
    }
}
