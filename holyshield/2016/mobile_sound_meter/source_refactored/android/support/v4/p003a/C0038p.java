package android.support.v4.p003a;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.text.TextUtils;
import android.util.Log;
import java.util.ArrayList;

/* renamed from: android.support.v4.a.p */
final class C0038p implements Parcelable {
    public static final Creator CREATOR;
    final int[] f254a;
    final int f255b;
    final int f256c;
    final String f257d;
    final int f258e;
    final int f259f;
    final CharSequence f260g;
    final int f261h;
    final CharSequence f262i;
    final ArrayList f263j;
    final ArrayList f264k;

    static {
        CREATOR = new C0039q();
    }

    public C0038p(Parcel parcel) {
        this.f254a = parcel.createIntArray();
        this.f255b = parcel.readInt();
        this.f256c = parcel.readInt();
        this.f257d = parcel.readString();
        this.f258e = parcel.readInt();
        this.f259f = parcel.readInt();
        this.f260g = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(parcel);
        this.f261h = parcel.readInt();
        this.f262i = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(parcel);
        this.f263j = parcel.createStringArrayList();
        this.f264k = parcel.createStringArrayList();
    }

    public C0038p(C0032j c0032j) {
        int i = 0;
        for (C0036n c0036n = c0032j.f205c; c0036n != null; c0036n = c0036n.f240a) {
            if (c0036n.f248i != null) {
                i += c0036n.f248i.size();
            }
        }
        this.f254a = new int[(i + (c0032j.f207e * 7))];
        if (c0032j.f214l) {
            i = 0;
            for (C0036n c0036n2 = c0032j.f205c; c0036n2 != null; c0036n2 = c0036n2.f240a) {
                int i2 = i + 1;
                this.f254a[i] = c0036n2.f242c;
                int i3 = i2 + 1;
                this.f254a[i2] = c0036n2.f243d != null ? c0036n2.f243d.f297g : -1;
                int i4 = i3 + 1;
                this.f254a[i3] = c0036n2.f244e;
                i2 = i4 + 1;
                this.f254a[i4] = c0036n2.f245f;
                i4 = i2 + 1;
                this.f254a[i2] = c0036n2.f246g;
                i2 = i4 + 1;
                this.f254a[i4] = c0036n2.f247h;
                if (c0036n2.f248i != null) {
                    int size = c0036n2.f248i.size();
                    i4 = i2 + 1;
                    this.f254a[i2] = size;
                    i2 = 0;
                    while (i2 < size) {
                        i3 = i4 + 1;
                        this.f254a[i4] = ((C0042t) c0036n2.f248i.get(i2)).f297g;
                        i2++;
                        i4 = i3;
                    }
                    i = i4;
                } else {
                    i = i2 + 1;
                    this.f254a[i2] = 0;
                }
            }
            this.f255b = c0032j.f212j;
            this.f256c = c0032j.f213k;
            this.f257d = c0032j.f216n;
            this.f258e = c0032j.f218p;
            this.f259f = c0032j.f219q;
            this.f260g = c0032j.f220r;
            this.f261h = c0032j.f221s;
            this.f262i = c0032j.f222t;
            this.f263j = c0032j.f223u;
            this.f264k = c0032j.f224v;
            return;
        }
        throw new IllegalStateException("Not on back stack");
    }

    public C0032j m335a(af afVar) {
        C0032j c0032j = new C0032j(afVar);
        int i = 0;
        int i2 = 0;
        while (i2 < this.f254a.length) {
            C0036n c0036n = new C0036n();
            int i3 = i2 + 1;
            c0036n.f242c = this.f254a[i2];
            if (af.f104a) {
                Log.v("FragmentManager", "Instantiate " + c0032j + " op #" + i + " base fragment #" + this.f254a[i3]);
            }
            int i4 = i3 + 1;
            i2 = this.f254a[i3];
            if (i2 >= 0) {
                c0036n.f243d = (C0042t) afVar.f110f.get(i2);
            } else {
                c0036n.f243d = null;
            }
            i3 = i4 + 1;
            c0036n.f244e = this.f254a[i4];
            i4 = i3 + 1;
            c0036n.f245f = this.f254a[i3];
            i3 = i4 + 1;
            c0036n.f246g = this.f254a[i4];
            int i5 = i3 + 1;
            c0036n.f247h = this.f254a[i3];
            i4 = i5 + 1;
            int i6 = this.f254a[i5];
            if (i6 > 0) {
                c0036n.f248i = new ArrayList(i6);
                i3 = 0;
                while (i3 < i6) {
                    if (af.f104a) {
                        Log.v("FragmentManager", "Instantiate " + c0032j + " set remove fragment #" + this.f254a[i4]);
                    }
                    i5 = i4 + 1;
                    c0036n.f248i.add((C0042t) afVar.f110f.get(this.f254a[i4]));
                    i3++;
                    i4 = i5;
                }
            }
            c0032j.f208f = c0036n.f244e;
            c0032j.f209g = c0036n.f245f;
            c0032j.f210h = c0036n.f246g;
            c0032j.f211i = c0036n.f247h;
            c0032j.m330a(c0036n);
            i++;
            i2 = i4;
        }
        c0032j.f212j = this.f255b;
        c0032j.f213k = this.f256c;
        c0032j.f216n = this.f257d;
        c0032j.f218p = this.f258e;
        c0032j.f214l = true;
        c0032j.f219q = this.f259f;
        c0032j.f220r = this.f260g;
        c0032j.f221s = this.f261h;
        c0032j.f222t = this.f262i;
        c0032j.f223u = this.f263j;
        c0032j.f224v = this.f264k;
        c0032j.m329a(1);
        return c0032j;
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeIntArray(this.f254a);
        parcel.writeInt(this.f255b);
        parcel.writeInt(this.f256c);
        parcel.writeString(this.f257d);
        parcel.writeInt(this.f258e);
        parcel.writeInt(this.f259f);
        TextUtils.writeToParcel(this.f260g, parcel, 0);
        parcel.writeInt(this.f261h);
        TextUtils.writeToParcel(this.f262i, parcel, 0);
        parcel.writeStringList(this.f263j);
        parcel.writeStringList(this.f264k);
    }
}
