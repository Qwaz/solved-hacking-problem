package android.support.v4.view;

import android.os.Parcel;
import android.support.v4.p001b.C0030c;
import android.support.v4.view.ViewPager.SavedState;

final class av implements C0030c {
    av() {
    }

    public /* synthetic */ Object m296a(Parcel parcel, ClassLoader classLoader) {
        return m298b(parcel, classLoader);
    }

    public /* synthetic */ Object[] m297a(int i) {
        return m299b(i);
    }

    public SavedState m298b(Parcel parcel, ClassLoader classLoader) {
        return new SavedState(parcel, classLoader);
    }

    public SavedState[] m299b(int i) {
        return new SavedState[i];
    }
}
