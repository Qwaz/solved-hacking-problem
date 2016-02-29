package android.support.v4.app;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.text.TextUtils;
import android.util.Log;
import java.util.ArrayList;

final class BackStackState implements Parcelable {
    public static final Creator CREATOR;
    final int[] f7a;
    final int f8b;
    final int f9c;
    final String f10d;
    final int f11e;
    final int f12f;
    final CharSequence f13g;
    final int f14h;
    final CharSequence f15i;

    static {
        CREATOR = new C0006d();
    }

    public BackStackState(Parcel parcel) {
        this.f7a = parcel.createIntArray();
        this.f8b = parcel.readInt();
        this.f9c = parcel.readInt();
        this.f10d = parcel.readString();
        this.f11e = parcel.readInt();
        this.f12f = parcel.readInt();
        this.f13g = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(parcel);
        this.f14h = parcel.readInt();
        this.f15i = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(parcel);
    }

    public BackStackState(C0016n c0016n, C0004b c0004b) {
        int i = 0;
        for (C0005c c0005c = c0004b.f82b; c0005c != null; c0005c = c0005c.f100a) {
            if (c0005c.f108i != null) {
                i += c0005c.f108i.size();
            }
        }
        this.f7a = new int[(i + (c0004b.f84d * 7))];
        if (c0004b.f91k) {
            i = 0;
            for (C0005c c0005c2 = c0004b.f82b; c0005c2 != null; c0005c2 = c0005c2.f100a) {
                int i2 = i + 1;
                this.f7a[i] = c0005c2.f102c;
                int i3 = i2 + 1;
                this.f7a[i2] = c0005c2.f103d != null ? c0005c2.f103d.f38f : -1;
                int i4 = i3 + 1;
                this.f7a[i3] = c0005c2.f104e;
                i2 = i4 + 1;
                this.f7a[i4] = c0005c2.f105f;
                i4 = i2 + 1;
                this.f7a[i2] = c0005c2.f106g;
                i2 = i4 + 1;
                this.f7a[i4] = c0005c2.f107h;
                if (c0005c2.f108i != null) {
                    int size = c0005c2.f108i.size();
                    i4 = i2 + 1;
                    this.f7a[i2] = size;
                    i2 = 0;
                    while (i2 < size) {
                        i3 = i4 + 1;
                        this.f7a[i4] = ((Fragment) c0005c2.f108i.get(i2)).f38f;
                        i2++;
                        i4 = i3;
                    }
                    i = i4;
                } else {
                    i = i2 + 1;
                    this.f7a[i2] = 0;
                }
            }
            this.f8b = c0004b.f89i;
            this.f9c = c0004b.f90j;
            this.f10d = c0004b.f93m;
            this.f11e = c0004b.f95o;
            this.f12f = c0004b.f96p;
            this.f13g = c0004b.f97q;
            this.f14h = c0004b.f98r;
            this.f15i = c0004b.f99s;
            return;
        }
        throw new IllegalStateException("Not on back stack");
    }

    public C0004b m10a(C0016n c0016n) {
        C0004b c0004b = new C0004b(c0016n);
        int i = 0;
        int i2 = 0;
        while (i2 < this.f7a.length) {
            C0005c c0005c = new C0005c();
            int i3 = i2 + 1;
            c0005c.f102c = this.f7a[i2];
            if (C0016n.f132a) {
                Log.v("FragmentManager", "Instantiate " + c0004b + " op #" + i + " base fragment #" + this.f7a[i3]);
            }
            int i4 = i3 + 1;
            i2 = this.f7a[i3];
            if (i2 >= 0) {
                c0005c.f103d = (Fragment) c0016n.f138f.get(i2);
            } else {
                c0005c.f103d = null;
            }
            i3 = i4 + 1;
            c0005c.f104e = this.f7a[i4];
            i4 = i3 + 1;
            c0005c.f105f = this.f7a[i3];
            i3 = i4 + 1;
            c0005c.f106g = this.f7a[i4];
            int i5 = i3 + 1;
            c0005c.f107h = this.f7a[i3];
            i4 = i5 + 1;
            int i6 = this.f7a[i5];
            if (i6 > 0) {
                c0005c.f108i = new ArrayList(i6);
                i3 = 0;
                while (i3 < i6) {
                    if (C0016n.f132a) {
                        Log.v("FragmentManager", "Instantiate " + c0004b + " set remove fragment #" + this.f7a[i4]);
                    }
                    i5 = i4 + 1;
                    c0005c.f108i.add((Fragment) c0016n.f138f.get(this.f7a[i4]));
                    i3++;
                    i4 = i5;
                }
            }
            c0004b.m79a(c0005c);
            i++;
            i2 = i4;
        }
        c0004b.f89i = this.f8b;
        c0004b.f90j = this.f9c;
        c0004b.f93m = this.f10d;
        c0004b.f95o = this.f11e;
        c0004b.f91k = true;
        c0004b.f96p = this.f12f;
        c0004b.f97q = this.f13g;
        c0004b.f98r = this.f14h;
        c0004b.f99s = this.f15i;
        c0004b.m78a(1);
        return c0004b;
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeIntArray(this.f7a);
        parcel.writeInt(this.f8b);
        parcel.writeInt(this.f9c);
        parcel.writeString(this.f10d);
        parcel.writeInt(this.f11e);
        parcel.writeInt(this.f12f);
        TextUtils.writeToParcel(this.f13g, parcel, 0);
        parcel.writeInt(this.f14h);
        TextUtils.writeToParcel(this.f15i, parcel, 0);
    }
}
