package android.support.v4.p003a;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;

/* renamed from: android.support.v4.a.am */
final class am implements Parcelable {
    public static final Creator CREATOR;
    ao[] f139a;
    int[] f140b;
    C0038p[] f141c;

    static {
        CREATOR = new an();
    }

    public am(Parcel parcel) {
        this.f139a = (ao[]) parcel.createTypedArray(ao.CREATOR);
        this.f140b = parcel.createIntArray();
        this.f141c = (C0038p[]) parcel.createTypedArray(C0038p.CREATOR);
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeTypedArray(this.f139a, i);
        parcel.writeIntArray(this.f140b);
        parcel.writeTypedArray(this.f141c, i);
    }
}
