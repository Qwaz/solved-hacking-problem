package android.support.v4.p003a;

import android.content.Context;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.util.Log;

/* renamed from: android.support.v4.a.ao */
final class ao implements Parcelable {
    public static final Creator CREATOR;
    final String f142a;
    final int f143b;
    final boolean f144c;
    final int f145d;
    final int f146e;
    final String f147f;
    final boolean f148g;
    final boolean f149h;
    final Bundle f150i;
    Bundle f151j;
    C0042t f152k;

    static {
        CREATOR = new ap();
    }

    public ao(Parcel parcel) {
        boolean z = true;
        this.f142a = parcel.readString();
        this.f143b = parcel.readInt();
        this.f144c = parcel.readInt() != 0;
        this.f145d = parcel.readInt();
        this.f146e = parcel.readInt();
        this.f147f = parcel.readString();
        this.f148g = parcel.readInt() != 0;
        if (parcel.readInt() == 0) {
            z = false;
        }
        this.f149h = z;
        this.f150i = parcel.readBundle();
        this.f151j = parcel.readBundle();
    }

    public ao(C0042t c0042t) {
        this.f142a = c0042t.getClass().getName();
        this.f143b = c0042t.f297g;
        this.f144c = c0042t.f305o;
        this.f145d = c0042t.f313w;
        this.f146e = c0042t.f314x;
        this.f147f = c0042t.f315y;
        this.f148g = c0042t.f268B;
        this.f149h = c0042t.f267A;
        this.f150i = c0042t.f299i;
    }

    public C0042t m205a(ac acVar, C0042t c0042t) {
        if (this.f152k != null) {
            return this.f152k;
        }
        Context g = acVar.m127g();
        if (this.f150i != null) {
            this.f150i.setClassLoader(g.getClassLoader());
        }
        this.f152k = C0042t.m340a(g, this.f142a, this.f150i);
        if (this.f151j != null) {
            this.f151j.setClassLoader(g.getClassLoader());
            this.f152k.f295e = this.f151j;
        }
        this.f152k.m353a(this.f143b, c0042t);
        this.f152k.f305o = this.f144c;
        this.f152k.f307q = true;
        this.f152k.f313w = this.f145d;
        this.f152k.f314x = this.f146e;
        this.f152k.f315y = this.f147f;
        this.f152k.f268B = this.f148g;
        this.f152k.f267A = this.f149h;
        this.f152k.f309s = acVar.f93d;
        if (af.f104a) {
            Log.v("FragmentManager", "Instantiated fragment " + this.f152k);
        }
        return this.f152k;
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel parcel, int i) {
        int i2 = 1;
        parcel.writeString(this.f142a);
        parcel.writeInt(this.f143b);
        parcel.writeInt(this.f144c ? 1 : 0);
        parcel.writeInt(this.f145d);
        parcel.writeInt(this.f146e);
        parcel.writeString(this.f147f);
        parcel.writeInt(this.f148g ? 1 : 0);
        if (!this.f149h) {
            i2 = 0;
        }
        parcel.writeInt(i2);
        parcel.writeBundle(this.f150i);
        parcel.writeBundle(this.f151j);
    }
}
