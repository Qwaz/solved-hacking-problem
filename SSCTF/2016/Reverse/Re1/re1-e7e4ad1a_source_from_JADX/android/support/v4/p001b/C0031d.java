package android.support.v4.p001b;

import android.os.Parcel;
import android.os.Parcelable.ClassLoaderCreator;

/* renamed from: android.support.v4.b.d */
class C0031d implements ClassLoaderCreator {
    private final C0030c f188a;

    public C0031d(C0030c c0030c) {
        this.f188a = c0030c;
    }

    public Object createFromParcel(Parcel parcel) {
        return this.f188a.m199a(parcel, null);
    }

    public Object createFromParcel(Parcel parcel, ClassLoader classLoader) {
        return this.f188a.m199a(parcel, classLoader);
    }

    public Object[] newArray(int i) {
        return this.f188a.m200a(i);
    }
}
