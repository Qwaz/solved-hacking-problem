package android.support.v7.widget;

import android.content.pm.ResolveInfo;
import java.math.BigDecimal;

public final class ab implements Comparable {
    public final ResolveInfo f1271a;
    public float f1272b;
    final /* synthetic */ C0307z f1273c;

    public ab(C0307z c0307z, ResolveInfo resolveInfo) {
        this.f1273c = c0307z;
        this.f1271a = resolveInfo;
    }

    public int m2458a(ab abVar) {
        return Float.floatToIntBits(abVar.f1272b) - Float.floatToIntBits(this.f1272b);
    }

    public /* synthetic */ int compareTo(Object obj) {
        return m2458a((ab) obj);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        return Float.floatToIntBits(this.f1272b) == Float.floatToIntBits(((ab) obj).f1272b);
    }

    public int hashCode() {
        return Float.floatToIntBits(this.f1272b) + 31;
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("[");
        stringBuilder.append("resolveInfo:").append(this.f1271a.toString());
        stringBuilder.append("; weight:").append(new BigDecimal((double) this.f1272b));
        stringBuilder.append("]");
        return stringBuilder.toString();
    }
}
