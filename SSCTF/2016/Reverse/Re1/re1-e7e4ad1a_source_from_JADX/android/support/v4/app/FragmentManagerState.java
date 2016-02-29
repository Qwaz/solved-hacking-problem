package android.support.v4.app;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;

final class FragmentManagerState implements Parcelable {
    public static final Creator CREATOR;
    FragmentState[] f59a;
    int[] f60b;
    BackStackState[] f61c;

    static {
        CREATOR = new C0019q();
    }

    public FragmentManagerState(Parcel parcel) {
        this.f59a = (FragmentState[]) parcel.createTypedArray(FragmentState.CREATOR);
        this.f60b = parcel.createIntArray();
        this.f61c = (BackStackState[]) parcel.createTypedArray(BackStackState.CREATOR);
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeTypedArray(this.f59a, i);
        parcel.writeIntArray(this.f60b);
        parcel.writeTypedArray(this.f61c, i);
    }
}
