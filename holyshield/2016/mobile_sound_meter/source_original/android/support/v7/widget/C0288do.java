package android.support.v7.widget;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.view.View.BaseSavedState;

/* renamed from: android.support.v7.widget.do */
public class C0288do extends BaseSavedState {
    public static final Creator CREATOR;
    int f1530a;
    boolean f1531b;

    static {
        CREATOR = new dp();
    }

    public C0288do(Parcel parcel) {
        super(parcel);
        this.f1530a = parcel.readInt();
        this.f1531b = parcel.readInt() != 0;
    }

    public C0288do(Parcelable parcelable) {
        super(parcelable);
    }

    public void writeToParcel(Parcel parcel, int i) {
        super.writeToParcel(parcel, i);
        parcel.writeInt(this.f1530a);
        parcel.writeInt(this.f1531b ? 1 : 0);
    }
}
