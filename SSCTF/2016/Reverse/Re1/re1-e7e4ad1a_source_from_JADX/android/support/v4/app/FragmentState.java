package android.support.v4.app;

import android.content.Context;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.util.Log;

final class FragmentState implements Parcelable {
    public static final Creator CREATOR;
    final String f62a;
    final int f63b;
    final boolean f64c;
    final int f65d;
    final int f66e;
    final String f67f;
    final boolean f68g;
    final boolean f69h;
    final Bundle f70i;
    Bundle f71j;
    Fragment f72k;

    static {
        CREATOR = new C0020r();
    }

    public FragmentState(Parcel parcel) {
        boolean z = true;
        this.f62a = parcel.readString();
        this.f63b = parcel.readInt();
        this.f64c = parcel.readInt() != 0;
        this.f65d = parcel.readInt();
        this.f66e = parcel.readInt();
        this.f67f = parcel.readString();
        this.f68g = parcel.readInt() != 0;
        if (parcel.readInt() == 0) {
            z = false;
        }
        this.f69h = z;
        this.f70i = parcel.readBundle();
        this.f71j = parcel.readBundle();
    }

    public FragmentState(Fragment fragment) {
        this.f62a = fragment.getClass().getName();
        this.f63b = fragment.f38f;
        this.f64c = fragment.f47o;
        this.f65d = fragment.f55w;
        this.f66e = fragment.f56x;
        this.f67f = fragment.f57y;
        this.f68g = fragment.f19B;
        this.f69h = fragment.f18A;
        this.f70i = fragment.f40h;
    }

    public Fragment m65a(C0011h c0011h, Fragment fragment) {
        if (this.f72k != null) {
            return this.f72k;
        }
        if (this.f70i != null) {
            this.f70i.setClassLoader(c0011h.getClassLoader());
        }
        this.f72k = Fragment.m12a((Context) c0011h, this.f62a, this.f70i);
        if (this.f71j != null) {
            this.f71j.setClassLoader(c0011h.getClassLoader());
            this.f72k.f36d = this.f71j;
        }
        this.f72k.m16a(this.f63b, fragment);
        this.f72k.f47o = this.f64c;
        this.f72k.f49q = true;
        this.f72k.f55w = this.f65d;
        this.f72k.f56x = this.f66e;
        this.f72k.f57y = this.f67f;
        this.f72k.f19B = this.f68g;
        this.f72k.f18A = this.f69h;
        this.f72k.f51s = c0011h.f111b;
        if (C0016n.f132a) {
            Log.v("FragmentManager", "Instantiated fragment " + this.f72k);
        }
        return this.f72k;
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel parcel, int i) {
        int i2 = 1;
        parcel.writeString(this.f62a);
        parcel.writeInt(this.f63b);
        parcel.writeInt(this.f64c ? 1 : 0);
        parcel.writeInt(this.f65d);
        parcel.writeInt(this.f66e);
        parcel.writeString(this.f67f);
        parcel.writeInt(this.f68g ? 1 : 0);
        if (!this.f69h) {
            i2 = 0;
        }
        parcel.writeInt(i2);
        parcel.writeBundle(this.f70i);
        parcel.writeBundle(this.f71j);
    }
}
