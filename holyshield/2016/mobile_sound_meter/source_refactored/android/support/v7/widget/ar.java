package android.support.v7.widget;

import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffColorFilter;
import android.support.v4.p012g.C0114g;

class ar extends C0114g {
    public ar(int i) {
        super(i);
    }

    private static int m2525b(int i, Mode mode) {
        return ((i + 31) * 31) + mode.hashCode();
    }

    PorterDuffColorFilter m2526a(int i, Mode mode) {
        return (PorterDuffColorFilter) m648a((Object) Integer.valueOf(m2525b(i, mode)));
    }

    PorterDuffColorFilter m2527a(int i, Mode mode, PorterDuffColorFilter porterDuffColorFilter) {
        return (PorterDuffColorFilter) m649a(Integer.valueOf(m2525b(i, mode)), porterDuffColorFilter);
    }
}
